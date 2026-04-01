<?php
declare(strict_types=1);

namespace App\Models;

class MediaModel
{
    private const BLURHASH_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz#$%*+,-.:;=?@[]^_{|}~';

    public static function upload(array $file, string $userId): ?array
    {
        $allowed = [
            'image/jpeg',
            'image/png',
            'image/gif',
            'image/webp',
            'image/avif',
            'image/heic',
            'image/heif',
            'video/mp4',
            'video/webm',
            'video/quicktime',
        ];
        $finfo   = new \finfo(FILEINFO_MIME_TYPE);
        $mime    = $finfo->file($file['tmp_name']) ?: '';
        if (!in_array($mime, $allowed)) return null;

        $max = AP_MAX_UPLOAD_MB * 1024 * 1024;
        if ($file['size'] > $max) return null;

        if (!is_dir(AP_MEDIA_DIR)) mkdir(AP_MEDIA_DIR, 0755, true);

        // Derive extension from validated MIME type — never trust the client filename
        $ext = match($mime) {
            'image/jpeg' => 'jpg',
            'image/png'  => 'png',
            'image/gif'  => 'gif',
            'image/webp' => 'webp',
            'image/avif' => 'avif',
            'image/heic' => 'heic',
            'image/heif' => 'heif',
            'video/mp4'  => 'mp4',
            'video/webm' => 'webm',
            'video/quicktime' => 'mov',
            default      => 'bin',
        };
        $name = uuid() . '.' . $ext;
        $dest = AP_MEDIA_DIR . '/' . $name;

        // move_uploaded_file só funciona com POST normal; para PATCH manual usamos rename/copy
        $moved = move_uploaded_file($file['tmp_name'], $dest);
        if (!$moved) {
            // Ficheiro criado manualmente via tempnam (PATCH multipart)
            $moved = rename($file['tmp_name'], $dest);
            if (!$moved) {
                $moved = copy($file['tmp_name'], $dest);
                if ($moved) @unlink($file['tmp_name']);
            }
        }
        if (!$moved) return null;

        $type = str_starts_with($mime, 'video/') ? 'video' : 'image';
        $url  = AP_MEDIA_URL . '/' . $name;
        $id   = uuid();
        $w    = null;
        $h    = null;
        $previewUrl = $url;
        $blurhash   = '';

        if ($type === 'image') {
            [$w, $h, $previewUrl, $blurhash] = self::prepareImageVariants($dest, $mime, $name);
        }

        DB::insert('media_attachments', [
            'id'          => $id,
            'user_id'     => $userId,
            'status_id'   => null,
            'type'        => $type,
            'url'         => $url,
            'preview_url' => $previewUrl,
            'description' => '',
            'blurhash'    => $blurhash,
            'width'       => $w,
            'height'      => $h,
            'created_at'  => now_iso(),
        ]);

        return DB::one('SELECT * FROM media_attachments WHERE id=?', [$id]);
    }

    public static function toMasto(array $m): array
    {
        $w = $m['width']  ? (int)$m['width']  : null;
        $h = $m['height'] ? (int)$m['height'] : null;

        $meta = ($w && $h)
            ? ['original' => ['width' => $w, 'height' => $h, 'aspect' => round($w / $h, 4)],
               'small'    => ['width' => $w, 'height' => $h, 'aspect' => round($w / $h, 4)]]
            : null;

        $remoteUrl = null;
        if (!empty($m['remote_url'])) {
            $remoteUrl = $m['remote_url'];
        } elseif (!empty($m['original_url']) && ($m['original_url'] ?? '') !== ($m['url'] ?? '')) {
            $remoteUrl = $m['original_url'];
        }

        $previewRemoteUrl = null;
        if (!empty($m['preview_remote_url'])) {
            $previewRemoteUrl = $m['preview_remote_url'];
        } elseif (!empty($m['original_preview_url']) && ($m['original_preview_url'] ?? '') !== ($m['preview_url'] ?? '')) {
            $previewRemoteUrl = $m['original_preview_url'];
        }

        return [
            'id'                 => $m['id'],
            'type'               => $m['type'],
            'url'                => $m['url'],
            'preview_url'        => $m['preview_url'],
            'remote_url'         => $remoteUrl,
            'preview_remote_url' => $previewRemoteUrl,
            'text_url'           => null,
            'description'        => $m['description'] ?? '',
            'blurhash'           => $m['blurhash'] ?: null,
            'meta'               => $meta,
        ];
    }

    private static function prepareImageVariants(string $dest, string $mime, string $name): array
    {
        $sz = @getimagesize($dest);
        $w  = $sz[0] ?? null;
        $h  = $sz[1] ?? null;
        $previewUrl = AP_MEDIA_URL . '/' . $name;
        $blurhash   = '';

        if (!extension_loaded('gd')) {
            return [$w, $h, $previewUrl, $blurhash];
        }

        $img = self::loadGdImage($dest, $mime);
        if (!$img) {
            return [$w, $h, $previewUrl, $blurhash];
        }

        $img = self::autoOrientImage($img, $dest, $mime);
        $w = imagesx($img);
        $h = imagesy($img);

        // Re-encoding the original strips EXIF and other metadata on supported formats.
        self::writeGdImage($img, $dest, $mime);

        $previewName = self::previewName($name, $mime);
        $previewPath = AP_MEDIA_DIR . '/' . $previewName;
        $previewMime = self::previewMime($mime);
        $previewExt  = pathinfo($previewName, PATHINFO_EXTENSION);
        $previewImg  = self::makeThumbnail($img, 800);
        self::writeGdImage($previewImg, $previewPath, $previewMime);

        $previewUrl = AP_MEDIA_URL . '/' . $previewName;
        $blurhash   = self::encodeAverageBlurhash($img);

        return [$w, $h, $previewUrl, $blurhash];
    }

    private static function autoOrientImage($img, string $path, string $mime)
    {
        if ($mime !== 'image/jpeg' || !function_exists('exif_read_data')) {
            return $img;
        }

        try {
            $exif = @exif_read_data($path);
        } catch (\Throwable) {
            return $img;
        }

        $orientation = (int)($exif['Orientation'] ?? 1);
        if ($orientation === 1) {
            return $img;
        }

        switch ($orientation) {
            case 2:
                imageflip($img, IMG_FLIP_HORIZONTAL);
                break;
            case 3:
                $rotated = imagerotate($img, 180, 0);
                if ($rotated !== false) $img = $rotated;
                break;
            case 4:
                imageflip($img, IMG_FLIP_VERTICAL);
                break;
            case 5:
                imageflip($img, IMG_FLIP_VERTICAL);
                $rotated = imagerotate($img, -90, 0);
                if ($rotated !== false) $img = $rotated;
                break;
            case 6:
                $rotated = imagerotate($img, -90, 0);
                if ($rotated !== false) $img = $rotated;
                break;
            case 7:
                imageflip($img, IMG_FLIP_HORIZONTAL);
                $rotated = imagerotate($img, -90, 0);
                if ($rotated !== false) $img = $rotated;
                break;
            case 8:
                $rotated = imagerotate($img, 90, 0);
                if ($rotated !== false) $img = $rotated;
                break;
        }

        return $img;
    }

    private static function loadGdImage(string $path, string $mime)
    {
        return match ($mime) {
            'image/jpeg' => function_exists('imagecreatefromjpeg') ? @imagecreatefromjpeg($path) : null,
            'image/png'  => function_exists('imagecreatefrompng') ? @imagecreatefrompng($path) : null,
            'image/gif'  => function_exists('imagecreatefromgif') ? @imagecreatefromgif($path) : null,
            'image/webp' => function_exists('imagecreatefromwebp') ? @imagecreatefromwebp($path) : null,
            default      => null,
        };
    }

    private static function writeGdImage($img, string $path, string $mime): void
    {
        if (in_array($mime, ['image/png', 'image/gif'], true)) {
            imagealphablending($img, false);
            imagesavealpha($img, true);
        }

        match ($mime) {
            'image/jpeg' => function_exists('imagejpeg') && @imagejpeg($img, $path, 92),
            'image/png'  => function_exists('imagepng')  && @imagepng($img, $path, 6),
            'image/gif'  => function_exists('imagegif')  && @imagegif($img, $path),
            'image/webp' => function_exists('imagewebp') && @imagewebp($img, $path, 90),
            default      => false,
        };
    }

    private static function previewMime(string $mime): string
    {
        return in_array($mime, ['image/jpeg', 'image/png', 'image/webp'], true) ? $mime : 'image/jpeg';
    }

    private static function previewName(string $name, string $mime): string
    {
        $base = preg_replace('/\.[^.]+$/', '', $name) ?: $name;
        $ext = match (self::previewMime($mime)) {
            'image/png'  => 'png',
            'image/webp' => 'webp',
            default      => 'jpg',
        };
        return $base . '.preview.' . $ext;
    }

    private static function makeThumbnail($src, int $maxDim)
    {
        $sw = imagesx($src);
        $sh = imagesy($src);
        $scale = min(1, $maxDim / max($sw, $sh));
        $tw = max(1, (int)round($sw * $scale));
        $th = max(1, (int)round($sh * $scale));
        $thumb = imagecreatetruecolor($tw, $th);
        imagealphablending($thumb, false);
        imagesavealpha($thumb, true);
        $transparent = imagecolorallocatealpha($thumb, 0, 0, 0, 127);
        imagefilledrectangle($thumb, 0, 0, $tw, $th, $transparent);
        imagecopyresampled($thumb, $src, 0, 0, 0, 0, $tw, $th, $sw, $sh);
        return $thumb;
    }

    private static function encodeAverageBlurhash($img): string
    {
        $w = imagesx($img);
        $h = imagesy($img);
        $stepX = max(1, (int)floor($w / 24));
        $stepY = max(1, (int)floor($h / 24));
        $count = 0;
        $r = 0.0;
        $g = 0.0;
        $b = 0.0;

        for ($y = 0; $y < $h; $y += $stepY) {
            for ($x = 0; $x < $w; $x += $stepX) {
                $rgb = imagecolorat($img, $x, $y);
                $r += self::srgbToLinear(($rgb >> 16) & 255);
                $g += self::srgbToLinear(($rgb >> 8) & 255);
                $b += self::srgbToLinear($rgb & 255);
                $count++;
            }
        }

        if ($count <= 0) return '';

        $dc = self::encodeDc($r / $count, $g / $count, $b / $count);
        return self::base83Encode(0, 1) . self::base83Encode(0, 1) . self::base83Encode($dc, 4);
    }

    private static function srgbToLinear(int $value): float
    {
        $v = $value / 255;
        return $v <= 0.04045 ? $v / 12.92 : (($v + 0.055) / 1.055) ** 2.4;
    }

    private static function linearToSrgb(float $value): int
    {
        $v = max(0, min(1, $value));
        $srgb = $v <= 0.0031308 ? $v * 12.92 : 1.055 * ($v ** (1 / 2.4)) - 0.055;
        return (int)round(max(0, min(255, $srgb * 255)));
    }

    private static function encodeDc(float $r, float $g, float $b): int
    {
        return (self::linearToSrgb($r) << 16) + (self::linearToSrgb($g) << 8) + self::linearToSrgb($b);
    }

    private static function base83Encode(int $value, int $length): string
    {
        $out = '';
        for ($i = 1; $i <= $length; $i++) {
            $digit = (int)floor($value / (83 ** ($length - $i))) % 83;
            $out .= self::BLURHASH_ALPHABET[$digit];
        }
        return $out;
    }
}
