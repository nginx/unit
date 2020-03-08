<?php

if (isset($_GET['chdir']) && $_GET['chdir'] != "") {
    if (!chdir($_GET['chdir'])) {
        echo "failure to chdir(" . $_GET['chdir'] . ")\n";
        exit;
    }
}

$opcache = -1;

if (function_exists('opcache_get_status')) {
    $opcache = opcache_get_status()->opcache_enabled;
}

header('X-OPcache: ' . $opcache);

print(getcwd());
?>
