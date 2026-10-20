<?php
/*
 * playlist.php — generates the M3U playlist.
 *
 * Channels are DRM DASH (Widevine/PlayReady, CENC). Players do the
 * DRM handshake themselves via the #KODIPROP license_key below.
 * HLS is not available; ?type=hls returns a truthful 406 JSON.
 */

include 'app/functions.php';
if (!file_exists($loginFilePath)) { http_response_code(401); echo 'Login required.'; exit; }

$type = strtolower(isset($_GET['type']) ? (string)$_GET['type'] : 'mpd');
if (!in_array($type, ['mpd', 'hls'], true)) { http_response_code(400); echo 'Unsupported type.'; exit; }
if ($type === 'hls') {
    http_response_code(406);
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    echo json_encode([
        'error'  => 'HLS_NOT_AVAILABLE',
        'reason' => 'Channels are DRM-protected DASH (Widevine/PlayReady, CENC). HLS would require decrypting segments, which this project does not do. Use the default MPD playlist with a player that supports inputstream.adaptive.',
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $origin_api);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 30);
$response = curl_exec($ch);
if ($response === false) { http_response_code(502); header('Content-Type: text/plain'); echo "# Error: origin API request failed\n"; exit; }

$data = json_decode($response, true);
$channels = $data['data']['list'] ?? [];
if (!is_array($channels)) { http_response_code(500); header('Content-Type: text/plain'); echo "# Error: Invalid or missing 'list' in response\n"; exit; }

$skip_ids_json = @file_get_contents($stb_only);
$skip_ids = json_decode($skip_ids_json, true);
if (!is_array($skip_ids)) $skip_ids = [];

$xff = getenv('TT_XFF') ?: '59.178.74.184';

if (stripos($userAgent, 'tivimate') !== false) {
    $liveheaders = '| X-Forwarded-For=' . $xff . ' | Origin=https://watch.tataplay.com | Referer=https://watch.tataplay.com/';
} elseif (stripos($userAgent, 'SparkleTV') !== false) {
    $liveheaders = '|X-Forwarded-For=' . $xff . '|Origin=https://watch.tataplay.com|Referer=https://watch.tataplay.com/';
} else {
    $liveheaders = '|X-Forwarded-For=' . $xff . '&Origin=https://watch.tataplay.com&Referer=https://watch.tataplay.com/';
}

$protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
$host  = $_SERVER['HTTP_HOST']   ?? 'localhost';
$port  = $_SERVER['SERVER_PORT'] ?? '80';
$sname = $_SERVER['SERVER_NAME'] ?? $host;

$host_with_port = $host;
if (($protocol === 'http'  && $port !== '80') ||
    ($protocol === 'https' && $port !== '443')) {
    $host_with_port = $sname . ':' . $port;
}

$request_uri = $_SERVER['REQUEST_URI'] ?? '/playlist.php';
$path        = dirname($request_uri);
$base_url    = "{$protocol}://{$host_with_port}{$path}";

$is_apache = function_exists('isApacheCompatible') ? isApacheCompatible() : false;
if ($is_apache) {
    $stream_path = file_exists('.htaccess') ? 'manifest.mpd' : 'get-mpd.php';
} else {
    $stream_path = 'get-mpd.php';
}

header('Content-Type: audio/x-mpegurl');
header('Content-Disposition: attachment; filename="playlist.m3u"');

foreach ($channels as $channel) {
    $channel_id = $channel['id'] ?? null;
    if (!$channel_id) continue;
    if (in_array($channel_id, $skip_ids, true)) continue;
    if (($channel['provider'] ?? '') === 'DistroTV') continue;

    $channel_name  = $channel['title']               ?? ('Channel ' . $channel_id);
    $channel_logo  = $channel['transparentImageUrl'] ?? '';
    $genres        = array_values(array_diff($channel['genres'] ?? [], ['HD']));
    $channel_genre = $genres[0] ?? 'General';

    $license_url = "https://tp.drmlive-01.workers.dev?id={$channel_id}";
    $dash_url    = $channel['streamData']['dashWidewinePlayUrl'] ?? '';

    $channel_live = ''; $use_proxy = false;
    if (!empty($dash_url)) {
        $dash_host = parse_url($dash_url, PHP_URL_HOST);
        if ($dash_host && strpos($dash_host, 'bpaita') === 0) {
            $channel_live = "{$base_url}/{$stream_path}?id={$channel_id}{$liveheaders}";
            $use_proxy = true;
        } else {
            $channel_live = $dash_url;
        }
    }

    echo "#EXTINF:-1 tvg-id=\"ts{$channel_id}\" tvg-logo=\"{$channel_logo}\" group-title=\"{$channel_genre}\",{$channel_name}\n";
    echo "#KODIPROP:inputstream.adaptive.license_type=clearkey\n";
    echo "#KODIPROP:inputstream.adaptive.license_key={$license_url}\n";
    if ($use_proxy) echo "#KODIPROP:inputstream.adaptive.manifest_type=mpd\n";
    echo "#EXTVLCOPT:http-user-agent={$ua}\n";
    echo "{$channel_live}\n\n";
}
