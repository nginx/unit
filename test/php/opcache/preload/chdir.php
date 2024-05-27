<?php

chdir(realpath(__DIR__ . '/..'));

opcache_compile_file('index.php');

?>
