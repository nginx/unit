<?php
if (isset($_GET['chdir'])) {
    chdir($_GET['chdir']);
}

echo file_get_contents('test.txt');
?>
