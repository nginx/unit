<?php

$pid = getmypid();

header('X-Pid: ' . $pid);

if (function_exists('opcache_is_script_cached')) {
    if (opcache_is_script_cached(__DIR__ . '/test.php')) {
        header('X-Cached: 1');
    } else {
        header('X-Cached: 0');
        opcache_compile_file(__DIR__ . '/test.php');
    }
} else {
    header('X-OPcache: -1');
}

?>
