<?php
header('Content-Length: 0');
header('X-Var-1: ' . $_GET['var1']);
header('X-Var-2: ' . (isset($_GET['var2']) ? $_GET['var2'] : 'not set'));
header('X-Var-3: ' . (isset($_GET['var3']) ? $_GET['var3'] : 'not set'));
header('X-Var-4: ' . (isset($_GET['var4']) ? $_GET['var4'] : 'not set'));
?>
