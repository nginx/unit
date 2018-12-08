<?php
if(isset($_GET['precision'])) {
    ini_set('precision', $_GET['precision']);
}

header('X-File: ' . php_ini_loaded_file());
header('X-Precision: ' . ini_get('precision'));
?>
