
# Minimalist PHP Directory Browser

A lightweight, secure, self-contained single-file PHP directory indexer designed for private local networks or VPN-backed server environments. It replaces standard web server
indexes with a modern and responsive interface featuring advanced path validation, symlink mapping, and persistent configuration.

> list.packed.php is a compressed version including it's own unpacker.


## Key Features

 - Network-Locked Security: Embedded IP subnet checking restricts access
   to local loopback or a designated private network range.
 - Virtual Traversal Jail: Navigation uses a logical breadcrumb system
   instead of raw filesystem relative paths (..), eliminating common
   directory traversal vulnerabilities.
 - Secure Symlink Support: Explicit allow-list framework for handling
   symlinks that point outside the primary document root.
 - Smart File Streaming: Dynamically streams files located outside the
   web document root using safe inline headers, while utilizing
   high-speed direct web server paths for inner assets.
 - Modern Frontend: Responsive, monospaced design featuring client-side
   real-time filtering, dynamic multi-column sorting (retaining folder
   hierarchy), and a persistent light/dark theme.
 - Local Network Clipboard: Universal "Copy Link" functionality equipped
   with a fallback mechanism for non-HTTPS local environments.

Configuration Guide

Open list.php and modify the configuration variables at the top of the file to fit your home lab environment.
**1. Network Restrictions**

	Configure your private subnet mask here. The script defaults to blocking anyone who isn't originating from localhost or this specific range.

    $client_ip = $_SERVER['REMOTE_ADDR'] ?? '';
    $ip_long   = ip2long($client_ip);
    $vpn_net   = ip2long('10.0.1.0');       // Change to your local/VPN subnet
    $vpn_mask  = ip2long('255.255.255.0'); // Subnet mask (/24)

**2. Base Directory Setup**

Set the hardcoded system root directory you want this script to index.

	$base_dir = realpath('/var/www/html'); // Absolute path to your target directory

**3. Extra Symlink Paths (Optional)**

If you have symlinks inside your $base_dir that point to external storage arrays or other directories (e.g., /mnt/media), add their absolute targets to this array. If left empty,
symlinks pointing outside the base directory will be rejected as broken or forbidden.
PHP

	$allowed_symlink_targets = [
    '/mnt/storage/media',
    '/var/log/custom_app',
	];

 **4. Logical Breadcrumbs vs. Disk Parentage**

When exploring directories via symlinks, the actual directory on disk might belong to an entirely different filesystem branch.

Standard system commands (cd ..) would drop you into the absolute parent of that physical directory.

This script tracks your path logically based on how you clicked into it. Hitting the "Up" button pops the last breadcrumb segment off your web session instead of executing a filesystem parent lookup, keeping your navigation path predictable and locked inside your UI state.

**5. State & Clipboard Management**

Session Persistence: Uses a 30-day cookie (last_dir) scoped to the    script's path, automatically returning you to your last browsed    directory upon revisiting.

Smart URL Copier: Determines if a file requires secure streaming (?dl=...) or direct web routing, constructing an accurate absolute link. Includes a raw textarea fallback mechanism to ensure copying still works seamlessly on unencrypted HTTP local instances where navigator.clipboard is restricted by browser security policies.

## Requirements & Dependencies

 - PHP Version: PHP **7.4** or higher recommended.
 - Permissions: The web server user (e.g., www-data) must have read ( r ) and execute ( x ) permissions on the target directories to list contents and traverse paths.
 - Optional PHP Extensions:
	
	**php-fileinfo** (highly recommended): Enables precise MIME-type detection when streaming files securely via the download query parameter.
   
	**php-posix**: Used to resolve and print system usernames instead of numeric UIDs in the "Owner" column.
