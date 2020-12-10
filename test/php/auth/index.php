<?php

header('X-Digest: ' . (isset($_SERVER['PHP_AUTH_DIGEST']) ? $_SERVER['PHP_AUTH_DIGEST'] : 'not set'));
header('X-User: ' . (isset($_SERVER['PHP_AUTH_USER']) ? $_SERVER['PHP_AUTH_USER'] : 'not set'));
header('X-Password: ' . (isset($_SERVER['PHP_AUTH_PW']) ? $_SERVER['PHP_AUTH_PW'] : 'not set'));

?>
