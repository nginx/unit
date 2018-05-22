<?php
header('Content-Length: 0');
header('X-Var-1: ' . $_GET['var1']);
header('X-Var-2: ' . $_GET['var2'] . isset($_GET['var2']));
header('X-Var-3: ' . $_GET['var3'] . isset($_GET['var3']));
header('X-Var-4: ' . $_GET['var4'] . isset($_GET['var4']));
?>
