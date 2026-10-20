<?php
/*
 * get-mpd.php — returns the DRM DASH manifest for a TataPlay channel.
 *
 * The upstream API exposes only DASH+DRM fields:
 *   data.dashPlayreadyPlayUrl   (PlayReady)
 *   streamData.dashWidewinePlayUrl (Widevine, used by playlist.php)
 *
 * No HLS rendition exists upstream, and producing one would require
 * decrypting CENC segments — which this project does not do.
 * ?format=m3u8 therefore returns a truthful 406 JSON.
 */

include 'app/functions.php';

if (!$id) { http_response_code(400); echo 'Missing content ID.'; exit; }
if (!file_exists($loginFilePath)) { http_response_code(401); echo 'Login required.'; exit; }

$loginData = json_decode(file_get_contents($loginFilePath), true);
if (!isset($loginData['data']['subscriberId']) || !isset($loginData['data']['userAuthenticateToken'])) {
    http_response_code(403); echo 'Invalid login data.'; exit;
}
$subscriberId = $loginData['data']['subscriberId'];
$userToken    = $loginData['data']['userAuthenticateToken'];

$format = strtolower(isset($_GET['format']) ? (string)$_GET['format'] : 'mpd');
if (!in_array($format, ['mpd', 'm3u8'], true)) {
    http_response_code(400); echo 'Unsupported format. Use ?format=mpd or ?format=m3u8.'; exit;
}

function tt_url_expiry(string $url): ?int {
    $q = [];
    parse_str(parse_url($url, PHP_URL_QUERY) ?? '', $q);
    if (isset($q['exp']) && is_numeric($q['exp'])) return (int)$q['exp'];
    if (isset($q['hdntl'])) {
        $h = [];
        parse_str(str_replace('~', '&', $q['hdntl']), $h);
        if (isset($h['exp']) && is_numeric($h['exp'])) return (int)$h['exp'];
    }
    return null;
}

$cacheData = file_exists($cachePath) ? json_decode(file_get_contents($cachePath), true) : [];
$useCache  = false;

if (isset($cacheData[$id])) {
    $cachedUrl = $cacheData[$id]['url'];
    $exp       = tt_url_expiry($cachedUrl);
    if ($exp && time() < $exp) { $mpdurl = $cachedUrl; $useCache = true; }
}

if (!$useCache) {
    $mpdurl = null; $hdntl = null;

    $headers = ['Authorization: Bearer ' . $userToken, 'subscriberId: ' . $subscriberId];
    $context = stream_context_create(['http' => ['method' => 'GET', 'header' => implode("\r\n", $headers)]]);
    $response = @file_get_contents($content_api, false, $context);
    if ($response === false) { http_response_code(500); echo 'Failed to fetch content data.'; exit; }

    $responseData = json_decode($response, true);
    if (!isset($responseData['data']['dashPlayreadyPlayUrl'])) {
        http_response_code(404); echo 'dashPlayreadyPlayUrl not found.'; exit;
    }

    $decryptedUrl = decryptUrl($responseData['data']['dashPlayreadyPlayUrl'], $aesKey);
    $decryptedUrl = str_replace('bpaita',   'bpaicatchupta', $decryptedUrl);
    $decryptedUrl = str_replace('manifest', 'Manifest',      $decryptedUrl);

    if (strpos($decryptedUrl, 'bpaicatchupta') === false) { header("Location: $decryptedUrl"); exit; }

    $ctx = stream_context_create(['http' => [
        'method' => 'GET',
        'header' => "User-Agent: $ua\r\nAccept: */*\r\nConnection: close\r\n",
        'follow_location' => 0, 'ignore_errors' => true,
    ]]);
    $respHeaders = @get_headers($decryptedUrl, 1, $ctx);

    if ($respHeaders && isset($respHeaders['Set-Cookie'])) {
        $cookies = is_array($respHeaders['Set-Cookie']) ? $respHeaders['Set-Cookie'] : [$respHeaders['Set-Cookie']];
        foreach ($cookies as $cookie) {
            if (stripos($cookie, 'hdntl=') !== false && preg_match('/hdntl=([^;]+)/', $cookie, $m)) {
                $hdntl = trim($m[1]); break;
            }
        }
    }
    if (!$hdntl && $respHeaders) {
        foreach ($respHeaders as $k => $v) {
            if (strtolower((string)$k) === 'hdntl') {
                if (is_array($v)) $v = end($v);
                $hdntl = trim($v); break;
            }
        }
    }

    if ($hdntl) {
        $cleanUrl = strtok($decryptedUrl, '?');
        $mpdurl = (strpos($hdntl, 'hdntl=') === 0)
                ? $cleanUrl . '?' . $hdntl
                : $cleanUrl . '?hdntl=' . $hdntl;
    }
    if (!$mpdurl) {
        if (!$respHeaders || !isset($respHeaders['Location'])) { header("Location: $decryptedUrl", true, 302); exit; }
        $location = is_array($respHeaders['Location']) ? end($respHeaders['Location']) : $respHeaders['Location'];
        $mpdurl   = strpos($location, '&') !== false ? substr($location, 0, strpos($location, '&')) : $location;
    }

    $cacheData[$id] = ['url' => $mpdurl, 'updated_at' => time()];
    file_put_contents($cachePath, json_encode($cacheData, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}

$mpdContext = stream_context_create(['http' => [
    'method' => 'GET',
    'header' => "User-Agent: $ua\r\nReferer: https://watch.tataplay.com/\r\nOrigin: https://watch.tataplay.com\r\n",
    'ignore_errors' => true,
]]);
$mpdContent = @file_get_contents($mpdurl, false, $mpdContext);
if ($mpdContent === false) { http_response_code(500); echo 'Failed to fetch MPD content.'; exit; }

$isDrm = (stripos($mpdContent, '<ContentProtection') !== false)
      || (stripos($mpdContent, 'cenc:default_KID')   !== false)
      || (stripos($mpdContent, 'mp4protection:2011') !== false);

if ($format === 'm3u8') {
    http_response_code(406);
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    header('X-TT-DRM: ' . ($isDrm ? 'cenc' : 'none'));
    echo json_encode([
        'error'         => 'HLS_NOT_AVAILABLE',
        'reason'        => $isDrm
            ? 'Upstream offers DRM-protected DASH (Widevine/PlayReady, CENC) only. Producing a playable HLS rendition would require decrypting segments, which this project does not do.'
            : 'Upstream content API for this asset exposes no HLS URL.',
        'content_id'    => (string)$id,
        'mpd_available' => true,
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

$baseUrl = dirname($mpdurl);
$processedManifest = $mpdContent;
if ($baseUrl && $baseUrl !== '.') {
    $processedManifest = preg_replace_callback(
        '/(<(?:BaseURL|Initialization|SegmentTemplate|SegmentURL)\b[^>]*?(?:href|sourceURL|initialization|media)\s*=\s*")(dash\/[^"]*)(")/i',
        fn($m) => $m[1] . $baseUrl . '/' . $m[2] . $m[3],
        $processedManifest
    );
}

$GetPssh = extractPsshFromManifest($processedManifest, $baseUrl, $ua);
if ($GetPssh) {
    $processedManifest = str_replace('mp4protection:2011', 'mp4protection:2011" cenc:default_KID="' . $GetPssh['kid'], $processedManifest);
    $processedManifest = str_replace('" value="PlayReady"/>', '"><cenc:pssh>' . $GetPssh['pr_pssh'] . '</cenc:pssh></ContentProtection>', $processedManifest);
    $processedManifest = str_replace('" value="Widevine"/>', '"><cenc:pssh>' . $GetPssh['pssh']    . '</cenc:pssh></ContentProtection>', $processedManifest);
}

header('Content-Security-Policy: default-src \'self\';');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('X-TT-Format: mpd');
header('X-TT-DRM: ' . ($isDrm ? 'cenc' : 'none'));
header('Content-Type: application/dash+xml');
header('Content-Disposition: inline; filename="tp' . urlencode($id) . '.mpd"');

echo $processedManifest;
