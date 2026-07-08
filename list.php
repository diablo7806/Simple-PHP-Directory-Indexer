<?php
// ==========================================
// 1. SECURITY & NETWORK CONFIGURATION
// ==========================================
$client_ip = $_SERVER['REMOTE_ADDR'] ?? '';

// Convert IPs to longs for precise bitwise subnet matching
$ip_long   = ip2long($client_ip);
$vpn_net   = ip2long('10.0.1.0'); // 10.0.0.0, 192.168.1.0, 172.23.0.0, etc.
$vpn_mask  = ip2long('255.255.255.0'); // /24 mask

$is_vpn   = ($ip_long !== false && ($ip_long & $vpn_mask) === ($vpn_net & $vpn_mask));
$is_local = ($client_ip === '127.0.0.1' || $client_ip === '::1');

// Kick anyone who isn't on the VPN or localhost, VPN is interchangeable with LAN. Developed in a VPN environment.
if (!$is_vpn && !$is_local) {
    header('HTTP/1.1 403 Forbidden');
    echo '<!DOCTYPE html><html lang="en"><head><title>403 Forbidden</title>';
    echo '<style>body{background:#121214;color:#ff4444;font-family:monospace;padding:50px;text-align:center;}div{border:1px solid #ff4444;display:inline-block;padding:20px;border-radius:5px;}</style></head>';
    echo '<body><div><h2>403 Forbidden</h2><p>Access Denied. You must be connected to the VPN/LAN pool to view this index.</p></div></body></html>';
    exit;
}

// Hardcoded directory browsing root
$base_dir = realpath('/var/www/html');

// Explicit allow-list of extra roots that symlinks under $base_dir are
// permitted to lead into. A symlinked directory or file only resolves
// successfully if its real, final target lands inside $base_dir OR inside
// one of these - anything else is refused, same as if the symlink weren't
// there. Add absolute paths here as needed, e.g. '/mnt/media'.
$allowed_symlink_targets = [
    '',
];

// Validate the config itself rather than silently dropping bad entries -
// a typo'd or missing allowed-folder path should be visible, not just
// look identical to "symlink permission denied" when someone hits it.
$allowed_roots = [];
$config_warnings = [];
foreach ($allowed_symlink_targets as $configured) {
    $resolved = realpath($configured);
    if ($resolved === false) {
        $config_warnings[] = 'Configured allowed folder "' . $configured . '" does not exist or can\'t be read - remove it or fix the path in $allowed_symlink_targets.';
    } elseif (!is_dir($resolved)) {
        $config_warnings[] = 'Configured allowed folder "' . $configured . '" is not a directory.';
    } else {
        $allowed_roots[] = $resolved;
    }
}

function path_is_allowed($real_path, $base_dir, $allowed_roots) {
    if ($real_path === $base_dir || strpos($real_path, $base_dir . DIRECTORY_SEPARATOR) === 0) {
        return true;
    }
    foreach ($allowed_roots as $root) {
        if ($real_path === $root || strpos($real_path, $root . DIRECTORY_SEPARATOR) === 0) {
            return true;
        }
    }
    return false;
}

/**
 * Files reached through an allow-listed symlink target can't be served via
 * a normal docroot-relative URL (the web server doesn't know that path
 * exists). So for those items we stream them ourselves via
 * ?dl=<absolute real path> instead of linking straight to a web path.
 * Files still inside $base_dir keep using the normal, faster,
 * web-server-served link.
 */
if (isset($_GET['dl'])) {
    $dl_path = realpath($_GET['dl']);

    if (!$dl_path || !is_file($dl_path) || !path_is_allowed($dl_path, $base_dir, $allowed_roots)) {
        header('HTTP/1.1 404 Not Found');
        exit('File not found.');
    }

    $mime = 'application/octet-stream';
    if (function_exists('finfo_open')) {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $detected = finfo_file($finfo, $dl_path);
        finfo_close($finfo);
        if ($detected) {
            $mime = $detected;
        }
    }

    header('Content-Type: ' . $mime);
    header('Content-Length: ' . filesize($dl_path));
    header('Content-Disposition: inline; filename="' . basename($dl_path) . '"');
    header('X-Content-Type-Options: nosniff');
    readfile($dl_path);
    exit;
}

// ==========================================
// 2. PATH PROCESSING & TRAVERSAL JAIL
// ==========================================
// Navigation is tracked as a "breadcrumb" - the sequence of folder names
// actually clicked through from $base_dir - rather than by asking the
// filesystem where the current directory "really" lives. This matters
// once symlinks are involved: a symlinked folder's real parent on disk is
// not the same as the folder you logically clicked in from, so any
// filesystem-based ".." would land you somewhere unexpected. The Up
// button below just pops the last breadcrumb segment instead.

// A bare request with no ?dir= at all (typing the URL fresh, or an old
// bookmark) resumes wherever you last were, via a cookie. An *explicit*
// request for root uses ?dir= (empty value) rather than no param at all,
// so "go home" and "haven't navigated yet" stay distinguishable.
if (!isset($_GET['dir'])) {
    if (!empty($_COOKIE['last_dir'])) {
        header('Location: ?dir=' . urlencode($_COOKIE['last_dir']));
        exit;
    }
    $raw_dir = '';
} else {
    $raw_dir = $_GET['dir'];
}
$requested_segments = array_filter(
    explode('/', str_replace('\\', '/', $raw_dir)),
                                   fn($p) => $p !== '' && $p !== '.' && $p !== '..'
);

$breadcrumb = '';
$target_dir = $base_dir;
$nav_warning = null;
foreach ($requested_segments as $segment) {
    $candidate_breadcrumb = $breadcrumb === '' ? $segment : $breadcrumb . '/' . $segment;
    $unresolved = $base_dir . '/' . $candidate_breadcrumb;
    $candidate_real = realpath($unresolved);

    if (!$candidate_real) {
        if (!file_exists($unresolved) && !is_link($unresolved)) {
            $nav_warning = 'Stopped at "' . $segment . '" - it doesn\'t exist.';
        } else {
            // Exists (or is a symlink) but realpath() still couldn't
            // resolve it - almost always a broken symlink target or a
            // permissions problem walking the path (e.g. the web server
            // user lacks execute/traverse rights on the link or a
            // directory in its target chain).
            $nav_warning = 'Stopped at "' . $segment . '" - couldn\'t resolve it (broken symlink, or the web server user lacks permission to traverse it).';
        }
        break;
    }

    if (!is_dir($candidate_real)) {
        $nav_warning = 'Stopped at "' . $segment . '" - it\'s not a directory.';
        break;
    }

    if (!path_is_allowed($candidate_real, $base_dir, $allowed_roots)) {
        $nav_warning = 'Stopped at "' . $segment . '" - it resolves outside the allowed folders and was blocked.';
        break;
    }

    if (!is_readable($candidate_real) || !is_executable($candidate_real)) {
        $nav_warning = 'Stopped at "' . $segment . '" - permission denied (the web server user can\'t read/traverse this folder).';
        break;
    }

    $breadcrumb = $candidate_breadcrumb;
    $target_dir = $candidate_real;
}

$escaped_root = strpos($target_dir, $base_dir) !== 0;
$relative_path = $breadcrumb;

// Remember where we ended up so a bare future visit (no ?dir= at all)
// resumes here instead of always starting at root. 30 day expiry, scoped
// to this script's path.
setcookie('last_dir', $relative_path, time() + 60 * 60 * 24 * 30, '/');

// 3. Read the directory and filter out system/self items
$raw_files = scandir($target_dir);
$directories = [];
$files = [];

foreach ($raw_files as $file) {
    if ($file === basename($_SERVER['SCRIPT_NAME']) || $file === '.' || $file === '..') {
        continue;
    }

    $full_path = $target_dir . DIRECTORY_SEPARATOR . $file;
    $is_dir = is_dir($full_path);

    // Gather file metadata
    $stat = @stat($full_path) ?: [];
    $size_bytes = $is_dir ? -1 : ($stat['size'] ?? 0);
    $size = $is_dir ? '[DIR]' : formatBytes($size_bytes);
    $raw_ext = pathinfo($file, PATHINFO_EXTENSION);
    $ext = $is_dir ? '' : strtoupper($raw_ext);

    // Owner resolution
    $owner = '-';
    if (function_exists('posix_getpwuid') && isset($stat['uid'])) {
        $owner_info = posix_getpwuid($stat['uid']);
        $owner = $owner_info['name'] ?? $stat['uid'];
    } elseif (isset($stat['uid'])) {
        $owner = $stat['uid'];
    }

    // Permissions
    $perms = isset($stat['mode']) ? substr(sprintf('%o', $stat['mode']), -4) : '----';

    // Symlink detection - purely informational (doesn't affect access
    // rules, which are already enforced via path_is_allowed above/below).
    $is_link = is_link($full_path);
    $link_target = null;
    if ($is_link) {
        $raw_target = readlink($full_path);
        $resolved_target = realpath($full_path);
        $link_target = $resolved_target ?: ($raw_target !== false ? $raw_target : 'unresolved');
    }

    // Build paths. The breadcrumb (not the real filesystem path) drives
    // navigation links, so folders keep working the same way regardless
    // of any symlink hops behind them. Individual files still need their
    // own real path checked, since a file can be a symlink even when its
    // containing folder isn't.
    $query_path = $relative_path ? $relative_path . '/' . $file : $file;
    $file_real = $is_dir ? null : (realpath($full_path) ?: $full_path);
    $file_escaped = $is_dir ? false : !path_is_allowed($file_real, $base_dir, $allowed_roots);

    if (!$is_dir && $file_escaped) {
        // Shouldn't normally happen (containing folder already passed the
        // allow-list check), but a file-level symlink pointing somewhere
        // disallowed should still be hidden rather than linked.
        continue;
    }

    if (!$is_dir && $escaped_root) {
        $file_href = '?dl=' . urlencode($file_real);
    } elseif (!$is_dir) {
        $web_link = '/' . $query_path;
        $file_href = htmlspecialchars(preg_replace('#/+#', '/', $web_link));
    } else {
        $file_href = null;
    }

    $item_data = [
        'name' => $file,
        'is_dir' => $is_dir,
        'ext' => $ext,
        'size' => $size,
        'size_bytes' => $size_bytes,
        'owner' => $owner,
        'perms' => $perms,
        'icon' => getIconHtml($is_dir, strtolower($raw_ext)),
        'href' => $is_dir ? '?dir=' . urlencode($query_path) : $file_href,
        'target' => $is_dir ? '_self' : '_blank',
        'is_link' => $is_link,
        'link_target' => $link_target
    ];

    if ($is_dir) {
        $directories[] = $item_data;
    } else {
        $files[] = $item_data;
    }
}

// Up-folder link, derived purely from the breadcrumb - always returns to
// wherever you actually clicked in from, never from filesystem parentage.
$up_href = null;
if ($relative_path !== '') {
    $up_segments = explode('/', $relative_path);
    array_pop($up_segments);
    $up_href = $up_segments ? '?dir=' . urlencode(implode('/', $up_segments)) : '?dir=';
}

// Clickable breadcrumb trail for the header - "Home / folder / subfolder".
// Built from the same breadcrumb string, so it's exact regardless of any
// symlink hops behind the scenes.
$breadcrumb_trail = [];
if ($relative_path !== '') {
    $accum = [];
    foreach (explode('/', $relative_path) as $seg) {
        $accum[] = $seg;
        $breadcrumb_trail[] = ['name' => $seg, 'href' => '?dir=' . urlencode(implode('/', $accum))];
    }
}

// Sort arrays
usort($directories, function($a, $b) {
    return strcasecmp($a['name'], $b['name']);
});
usort($files, function($a, $b) {
    return strcasecmp($a['name'], $b['name']);
});

$final_list = array_merge($directories, $files);

function formatBytes($bytes, $precision = 1) {
    if ($bytes <= 0) return '0 B';
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    return round($bytes / pow(1024, $pow), $precision) . ' ' . $units[$pow];
}

// Inline SVG Icon Generator based on file extensions
function getIconHtml($is_dir, $ext) {
    if ($is_dir) {
        return '<svg class="icon icon-dir" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>';
    }

    $icon_types = [
        'image' => ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'ico'],
        'video' => ['mp4', 'mkv', 'avi', 'mov', 'flv', 'webm'],
        'audio' => ['mp3', 'wav', 'flac', 'ogg', 'm4a'],
        'archive' => ['zip', 'rar', '7z', 'tar', 'gz'],
        'code' => ['php', 'js', 'html', 'css', 'json', 'py', 'sh', 'yaml', 'xml']
    ];

    if (in_array($ext, $icon_types['image'])) {
        return '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>';
    } elseif (in_array($ext, $icon_types['video'])) {
        return '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg>';
    } elseif (in_array($ext, $icon_types['audio'])) {
        return '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/></svg>';
    } elseif (in_array($ext, $icon_types['archive'])) {
        return '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/></svg>';
    } elseif (in_array($ext, $icon_types['code'])) {
        return '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>';
    }

    // Default File Generic Icon
    return '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>';
}

$display_path = '/' . $relative_path;
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Index of <?php echo htmlspecialchars($display_path); ?></title>
<style>
:root {
    --bg-color: #121214;
    --panel-color: #1a1a1e;
    --text-main: #b3b3b3;
    --text-muted: #62626a;
    --accent-dir: #00aaff;
    --accent-file: #00ff00;
    --border-color: #2a2a30;
    --hover-color: #222227;
    --input-bg: #222227;
}
body.light-theme {
    --bg-color: #f4f4f7;
    --panel-color: #ffffff;
    --text-main: #2d2d30;
    --text-muted: #71717a;
    --accent-dir: #007acc;
    --accent-file: #008800;
    --border-color: #e4e4e7;
    --hover-color: #f4f4f5;
    --input-bg: #f4f4f5;
}
body { font-family: 'SF Mono', Monaco, Consolas, monospace; background: var(--bg-color); color: var(--text-main); margin: 0; padding: 40px 20px; transition: background 0.2s, color 0.2s; }
.container { max-width: 1100px; margin: 0 auto; background: var(--panel-color); padding: 24px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); border: 1px solid var(--border-color); }

.header-controls { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; gap: 15px; flex-wrap: wrap; }
h2 { margin: 0; font-weight: 500; font-size: 1.3rem; letter-spacing: -0.5px; }

.toolbar { display: flex; gap: 10px; align-items: center; }
.search-box { background: var(--input-bg); border: 1px solid var(--border-color); color: var(--text-main); padding: 8px 14px; border-radius: 6px; font-family: inherit; font-size: 0.85rem; width: 220px; outline: none; }
.search-box:focus { border-color: var(--accent-dir); }

.theme-btn { background: none; border: 1px solid var(--border-color); color: var(--text-main); padding: 7px 12px; border-radius: 6px; cursor: pointer; font-family: inherit; font-size: 0.85rem; display: flex; align-items: center; justify-content: center; }
.theme-btn:hover { background: var(--hover-color); }

table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }
th { padding: 12px 8px; color: var(--text-muted); font-weight: 600; font-size: 0.8rem; text-transform: uppercase; border-bottom: 2px solid var(--border-color); }
td { padding: 10px 8px; border-bottom: 1px solid var(--border-color); vertical-align: middle; }
tr:hover td { background: var(--hover-color); }

.name-cell { display: flex; align-items: center; gap: 10px; }
.icon { width: 16px; height: 16px; flex-shrink: 0; color: var(--text-muted); }
.icon-dir { color: var(--accent-dir); }

a { text-decoration: none; display: inline-block; }
a:hover { text-decoration: underline; }
.dir-link { color: var(--accent-dir); font-weight: bold; }
.file-link { color: var(--accent-file); }
.text-muted { color: var(--text-muted); }
.col-shrink { width: 1%; white-space: nowrap; }

.copy-btn { background: none; border: 1px solid var(--border-color); color: var(--text-muted); padding: 3px 8px; border-radius: 4px; cursor: pointer; font-family: inherit; font-size: 0.75rem; transition: all 0.15s ease; }
.copy-btn:hover { border-color: var(--text-main); color: var(--text-main); }
.copy-btn:active { transform: scale(0.95); }

.nav-warning { background: rgba(255, 170, 0, 0.1); border: 1px solid #ffaa00; color: #ffaa00; padding: 10px 14px; border-radius: 6px; font-size: 0.85rem; margin-bottom: 16px; }
body.light-theme .nav-warning { background: rgba(180, 120, 0, 0.08); color: #8a5a00; border-color: #cc8800; }

.link-badge { display: inline-flex; align-items: center; justify-content: center; font-size: 0.7rem; padding: 1px 6px; border-radius: 4px; border: 1px solid var(--border-color); color: var(--text-muted); flex-shrink: 0; cursor: help; }

.breadcrumb { display: flex; align-items: baseline; gap: 6px; flex-wrap: wrap; font-weight: 500; font-size: 1.05rem; }
.crumb { color: var(--accent-dir); }
.crumb-current { color: var(--text-main); font-weight: 600; }
.crumb-sep { color: var(--text-muted); }

th.sortable { cursor: pointer; user-select: none; }
th.sortable:hover { color: var(--text-main); }
th.sortable .sort-arrow { display: inline-block; width: 1em; opacity: 0.5; }
</style>
</head>
<body>

<div class="container">
<?php if ($nav_warning !== null): ?>
<div class="nav-warning">⚠ <?php echo htmlspecialchars($nav_warning); ?></div>
<?php endif; ?>
<?php foreach ($config_warnings as $cw): ?>
<div class="nav-warning">⚠ <?php echo htmlspecialchars($cw); ?></div>
<?php endforeach; ?>
<div class="header-controls">
<h2 class="breadcrumb">
<a href="?dir=" class="crumb">Home</a>
<?php foreach ($breadcrumb_trail as $i => $crumb): ?>
<span class="crumb-sep">/</span>
<?php if ($i === count($breadcrumb_trail) - 1): ?>
<span class="crumb crumb-current"><?php echo htmlspecialchars($crumb['name']); ?></span>
<?php else: ?>
<a href="<?php echo htmlspecialchars($crumb['href']); ?>" class="crumb"><?php echo htmlspecialchars($crumb['name']); ?></a>
<?php endif; ?>
<?php endforeach; ?>
</h2>
<div class="toolbar">
<?php if ($up_href !== null): ?>
<a href="<?php echo htmlspecialchars($up_href); ?>" class="theme-btn" title="Up one folder">⬆ Up</a>
<?php endif; ?>
<input type="text" id="search" class="search-box" placeholder="Filter files...">
<button class="theme-btn" id="themeToggle" title="Toggle Light/Dark Mode">🌓</button>
</div>
</div>

<table>
<thead>
<tr>
<th data-sort="name" class="sortable">Name <span class="sort-arrow"></span></th>
<th class="col-shrink sortable" data-sort="ext">Ext <span class="sort-arrow"></span></th>
<th class="col-shrink sortable" data-sort="size" style="text-align: right;">Size <span class="sort-arrow"></span></th>
<th class="col-shrink sortable" data-sort="owner">Owner <span class="sort-arrow"></span></th>
<th class="col-shrink">Perms</th>
<th class="col-shrink" style="text-align: center;">Actions</th>
</tr>
</thead>
<tbody id="file-table-body">
<?php foreach ($final_list as $item): ?>
<tr class="filterable-row"
data-name="<?php echo htmlspecialchars($item['name']); ?>"
data-ext="<?php echo htmlspecialchars($item['ext']); ?>"
data-size="<?php echo (int) $item['size_bytes']; ?>"
data-owner="<?php echo htmlspecialchars((string) $item['owner']); ?>"
data-isdir="<?php echo $item['is_dir'] ? 1 : 0; ?>">
<td>
<div class="name-cell">
<?php echo $item['icon']; ?>
<a href="<?php echo $item['href']; ?>"
target="<?php echo $item['target']; ?>"
class="item-name-link <?php echo $item['is_dir'] ? 'dir-link' : 'file-link'; ?>">
<?php echo htmlspecialchars($item['name']) . ($item['is_dir'] ? '/' : ''); ?>
</a>
<?php if ($item['is_link']): ?>
<span class="link-badge" title="Symlink &#8594; <?php echo htmlspecialchars($item['link_target']); ?>">LINK</span>
<?php endif; ?>
</div>
</td>
<td class="col-shrink text-muted"><?php echo htmlspecialchars($item['ext']); ?></td>
<td class="col-shrink <?php echo $item['is_dir'] ? 'text-muted' : ''; ?>" style="text-align: right;"><?php echo $item['size']; ?></td>
<td class="col-shrink text-muted"><?php echo htmlspecialchars($item['owner']); ?></td>
<td class="col-shrink text-muted"><?php echo htmlspecialchars($item['perms']); ?></td>
<td class="col-shrink" style="text-align: center;">
<button class="copy-btn" onclick="copyLink(this, '<?php echo addslashes($item['href']); ?>', <?php echo $item['is_dir'] ? 'true' : 'false'; ?>)">Copy Link</button>
</td>
</tr>
<?php endforeach; ?>
</tbody>
</table>
</div>

<script>
// Column Sorting - directories stay grouped first when sorting by Name,
// since that matches how the list is generated by default; other columns
// sort by raw value across everything.
let currentSort = { key: 'name', dir: 1 };
function sortTable(key) {
    const tbody = document.getElementById('file-table-body');
    const rows = Array.from(tbody.querySelectorAll('tr'));

    if (currentSort.key === key) {
        currentSort.dir *= -1;
    } else {
        currentSort = { key, dir: 1 };
    }

    rows.sort((a, b) => {
        if (key === 'name') {
            const aDir = a.dataset.isdir === '1', bDir = b.dataset.isdir === '1';
    if (aDir !== bDir) return aDir ? -1 : 1;
        }
        let av = a.dataset[key], bv = b.dataset[key];
    if (key === 'size') {
        return (parseInt(av, 10) - parseInt(bv, 10)) * currentSort.dir;
    }
    return av.localeCompare(bv, undefined, { numeric: true, sensitivity: 'base' }) * currentSort.dir;
    });

    rows.forEach(r => tbody.appendChild(r));

    document.querySelectorAll('th.sortable .sort-arrow').forEach(el => el.textContent = '');
    const activeArrow = document.querySelector(`th[data-sort="${key}"] .sort-arrow`);
    if (activeArrow) activeArrow.textContent = currentSort.dir === 1 ? '▲' : '▼';
}
document.querySelectorAll('th.sortable').forEach(th => {
    th.addEventListener('click', () => sortTable(th.dataset.sort));
});

// Real-time UI Text Filter Functionality
document.getElementById('search').addEventListener('input', function(e) {
    const query = e.target.value.toLowerCase().trim();
    document.querySelectorAll('.filterable-row').forEach(row => {
        const nameText = row.querySelector('.item-name-link').innerText.toLowerCase();
        row.style.display = nameText.includes(query) ? '' : 'none';
    });
});

// Light / Dark Theme Syncing via LocalStorage
const toggleBtn = document.getElementById('themeToggle');
if (localStorage.getItem('theme') === 'light') {
    document.body.classList.add('light-theme');
}
toggleBtn.addEventListener('click', () => {
    document.body.classList.toggle('light-theme');
    if (document.body.classList.contains('light-theme')) {
        localStorage.setItem('theme', 'light');
    } else {
        localStorage.setItem('theme', 'dark');
    }
});

// HTTP Local Network Compatible Clipboard Management
function copyLink(btn, href, isDir) {
    const url = new URL(window.location.href);
    const isQueryLink = href.startsWith('?');
    let fullUrl = isQueryLink ? (url.origin + url.pathname + href) : (url.origin + href);

    const successFeedback = () => {
        const originalText = btn.innerText;
        btn.innerText = 'Copied!';
        btn.style.borderColor = '#00ff00';
        btn.style.color = '#00ff00';
        setTimeout(() => {
            btn.innerText = originalText;
            btn.style.borderColor = '';
        btn.style.color = '';
        }, 1200);
    };

    if (!navigator.clipboard) {
        const textArea = document.createElement("textarea");
        textArea.value = fullUrl;
        textArea.style.position = "fixed";
        textArea.style.opacity = "0";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        try {
            if (document.execCommand('copy')) successFeedback();
        } catch (err) {
            alert('Fallback copy execution error: ' + err);
        }
        document.body.removeChild(textArea);
    } else {
        navigator.clipboard.writeText(fullUrl).then(() => {
            successFeedback();
        }).catch(() => alert('Modern clipboard API rejected operation.'));
    }
}
</script>

</body>
</html>
