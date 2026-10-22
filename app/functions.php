<?php

$id = $_GET['id'] ?? null;
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
$loginFilePath = 'app/data/login.json';
$cachePath = 'app/data/cache_urls.json';
$cacheKidPath = 'app/data/cache_kid.json';
$origin_json = 'app/origin.json';
$aesKey = 'aesEncryptionKey';
$ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36';
$content_api = 'https://tb.tapi.videoready.tv/content-detail/api/partner/cdn/player/details/chotiluli/' . ($id ?? '');
$origin_api = 'https://tp.drmlive-01.workers.dev/origin';
$stb_only = 'https://tp.drmlive-01.workers.dev/stb_only';

function getProxyUrl(): ?string {
    $envProxy = getenv('TT_PROXY');
    if ($envProxy) {
        return $envProxy;
    }
    // Check if local proxy forwarder is reachable on Docker host or localhost
    $sock = @fsockopen('172.17.0.1', 8888, $errno, $errstr, 0.2);
    if ($sock) {
        fclose($sock);
        return 'http://172.17.0.1:8888';
    }
    $sock = @fsockopen('172.20.0.1', 8888, $errno, $errstr, 0.2);
    if ($sock) {
        fclose($sock);
        return 'http://172.20.0.1:8888';
    }
    $sock = @fsockopen('127.0.0.1', 8888, $errno, $errstr, 0.2);
    if ($sock) {
        fclose($sock);
        return 'http://127.0.0.1:8888';
    }
    return null;
}

function fetchHttp(string $url, array $opts = []): array {
    $ch = curl_init($url);
    $method = strtoupper($opts['method'] ?? 'GET');
    $headers = $opts['headers'] ?? [];
    $timeout = (int)($opts['timeout'] ?? 15);
    $useProxy = $opts['use_proxy'] ?? true;
    $proxy = $useProxy ? ($opts['proxy'] ?? getProxyUrl()) : null;

    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);

    if (!empty($opts['body'])) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, $opts['body']);
    }
    if ($proxy) {
        curl_setopt($ch, CURLOPT_PROXY, $proxy);
    }
    if (!empty($headers)) {
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    }

    $raw = curl_exec($ch);
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $err = curl_error($ch);

    $respHeaders = substr($raw ?: '', 0, $headerSize);
    $body = substr($raw ?: '', $headerSize);

    return [
        'status' => $status,
        'headers' => $respHeaders,
        'body' => $body,
        'error' => $err
    ];
}

function decryptUrl(?string $encryptedUrl, string $aesKey) {
    if (!$encryptedUrl) return false;
    $cleanEncrypted = preg_replace('/#.*$/', '', $encryptedUrl);
    $decoded = base64_decode($cleanEncrypted);
    $decryptedUrl = openssl_decrypt($decoded, 'aes-128-ecb', $aesKey, OPENSSL_RAW_DATA);
    if ($decryptedUrl === false) return false;
    return $decryptedUrl;
}

function parseInitSegmentBoxes(string $data): array {
    $result = ['wv_pssh' => null, 'pr_pssh' => null, 'kid' => null];
    $WV_UUID = 'edef8ba979d64acea3c827dcd51d21ed';
    $PR_UUID = '9a04f07998404286ab92e65be0885f95';

    $offset = 0;
    $len = strlen($data);
    while (($pos = strpos($data, 'pssh', $offset)) !== false) {
        $boxStart = $pos - 4;
        if ($boxStart < 0) { $offset = $pos + 4; continue; }
        $size = unpack('N', substr($data, $boxStart, 4))[1] ?? 0;
        if ($size < 12 || $boxStart + $size > $len) { $offset = $pos + 4; continue; }
        $boxData = substr($data, $boxStart, $size);
        $sysIdHex = strtolower(bin2hex(substr($boxData, 12, 16)));
        if ($sysIdHex === $WV_UUID) {
            $result['wv_pssh'] = base64_encode($boxData);
            // In Widevine PSSH, field 2 (0x12, len, kid) contains 16-byte KID
            $kidPos = strpos($boxData, "\x12\x10");
            if ($kidPos !== false && $kidPos + 18 <= strlen($boxData)) {
                $kidHex = bin2hex(substr($boxData, $kidPos + 2, 16));
                $result['kid'] = sprintf(
                    '%s-%s-%s-%s-%s',
                    substr($kidHex, 0, 8),
                    substr($kidHex, 8, 4),
                    substr($kidHex, 12, 4),
                    substr($kidHex, 16, 4),
                    substr($kidHex, 20)
                );
            }
        } elseif ($sysIdHex === $PR_UUID) {
            $result['pr_pssh'] = base64_encode($boxData);
        }
        $offset = $boxStart + $size;
    }

    if (!$result['kid']) {
        $tencPos = strpos($data, 'tenc');
        if ($tencPos !== false) {
            $boxStart = $tencPos - 4;
            $boxData = substr($data, $boxStart);
            $version = ord($boxData[8] ?? "\x00");
            $kidOffset = ($version === 0) ? 12 : 16;
            if (strlen($boxData) >= $kidOffset + 16) {
                $kidHex = bin2hex(substr($boxData, $kidOffset, 16));
                $result['kid'] = sprintf(
                    '%s-%s-%s-%s-%s',
                    substr($kidHex, 0, 8),
                    substr($kidHex, 8, 4),
                    substr($kidHex, 12, 4),
                    substr($kidHex, 16, 4),
                    substr($kidHex, 20)
                );
            }
        }
    }
    return $result;
}

function extractPsshFromManifest(string $content, string $cdnBase, string $authQuery, string $userAgent): ?array {
    global $cacheKidPath;

    // Check if PSSH already embedded in MPD
    if (($xml = @simplexml_load_string($content)) !== false) {
        $namespaces = $xml->getNamespaces(true);
        $mpdNs  = $namespaces['']     ?? 'urn:mpeg:dash:schema:mpd:2011';
        $cencNs = $namespaces['cenc'] ?? 'urn:mpeg:cenc:2013';
        $xml->registerXPathNamespace('mpd',  $mpdNs);
        $xml->registerXPathNamespace('cenc', $cencNs);
        $wv = $xml->xpath('//mpd:ContentProtection[contains(translate(@schemeIdUri,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz"),"edef8ba9")]/cenc:pssh');
        $wvPssh = $wv ? trim((string)$wv[0]) : null;
        $pr = $xml->xpath('//mpd:ContentProtection[contains(translate(@schemeIdUri,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz"),"9a04f079")]/cenc:pssh');
        $prPssh = $pr ? trim((string)$pr[0]) : null;
        $kidNodes = $xml->xpath('//mpd:ContentProtection[@cenc:default_KID]');
        $kid = $kidNodes ? (string)$kidNodes[0]['default_KID'] : null;
        if ($wvPssh || $prPssh) {
            return ['wv_pssh' => $wvPssh, 'pr_pssh' => $prPssh, 'kid' => $kid];
        }

        // Locate init segment template
        $initAttr = '';
        $repId = '';
        foreach ($xml->Period->AdaptationSet as $set) {
            if ((string)$set['contentType'] === 'audio' || (string)$set['mimeType'] === 'audio/mp4') {
                foreach ($set->Representation as $rep) {
                    $template = $rep->SegmentTemplate ?? null;
                    if ($template && isset($template['initialization'])) {
                        $initAttr = (string)$template['initialization'];
                        $repId = (string)$rep['id'];
                        break 2;
                    }
                }
            }
        }

        if ($initAttr && $repId) {
            $initFilename = str_replace('$RepresentationID$', $repId, $initAttr);
            $cacheKey = md5($cdnBase . '/' . $initFilename);

            $kidCache = file_exists($cacheKidPath) ? json_decode(file_get_contents($cacheKidPath), true) ?? [] : [];
            if (isset($kidCache[$cacheKey]) && (time() - ($kidCache[$cacheKey]['timestamp'] ?? 0)) < 86400) {
                return $kidCache[$cacheKey]['data'];
            }

            $initUrl = rtrim($cdnBase, '/') . '/dash/' . ltrim($initFilename, '/');
            if ($authQuery) {
                $initUrl .= '?' . $authQuery;
            }

            $resp = fetchHttp($initUrl, [
                'headers' => [
                    "User-Agent: $userAgent",
                    'Origin: https://watch.tataplay.com',
                    'Referer: https://watch.tataplay.com/'
                ],
                'timeout' => 10
            ]);

            if ($resp['status'] === 200 && strlen($resp['body']) > 100) {
                $parsed = parseInitSegmentBoxes($resp['body']);
                if ($parsed['wv_pssh'] || $parsed['pr_pssh']) {
                    $kidCache[$cacheKey] = ['data' => $parsed, 'timestamp' => time()];
                    @mkdir(dirname($cacheKidPath), 0777, true);
                    file_put_contents($cacheKidPath, json_encode($kidCache, JSON_PRETTY_PRINT));
                    return $parsed;
                }
            }
        }
    }
    return null;
}

function isApacheCompatible(): bool {
    $software = $_SERVER['SERVER_SOFTWARE'] ?? '';
    return stripos($software, 'Apache') !== false || stripos($software, 'LiteSpeed') !== false;
}
