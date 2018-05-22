<?php
header('Content-Length: 0');
header('X-Var-1: ' . $_POST['var1']);
header('X-Var-2: ' . $_POST['var2'] . isset($_POST['var2']));
header('X-Var-3: ' . $_POST['var3'] . isset($_POST['var3']));
?>
