<?php
header('Content-Length: 0');
header('X-Var-1: ' . $_POST['var1']);
header('X-Var-2: ' . (isset($_POST['var2']) ? $_POST['var2'] : 'not set'));
header('X-Var-3: ' . (isset($_POST['var3']) ? $_POST['var3'] : 'not set'));
?>
