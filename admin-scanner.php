<?php
// Security headers
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: SAMEORIGIN");

// Function to safely scan URLs
function scanUrl($url, $wordlist_path = 'list.txt', $proxy = null, $delay = 0) {
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        return ["error" => "Invalid URL format. Please include http:// or https://"];
    }

    // Ensure URL ends with /
    $url = rtrim($url, '/') . '/';
    
    // Validate and load wordlist
    if (!file_exists($wordlist_path)) {
        return ["error" => "Wordlist file not found"];
    }
    
    $results = [];
    $wordlist = file($wordlist_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    
    // Configure curl options
    $curl_options = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    ];
    
    if ($proxy) {
        $curl_options[CURLOPT_PROXY] = $proxy;
    }
    
    foreach ($wordlist as $path) {
        $ch = curl_init($url . $path);
        curl_setopt_array($ch, $curl_options);
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        
        if ($http_code == 200) {
            $results[] = [
                "path" => $path,
                "status" => $http_code,
                "url" => $url . $path
            ];
        }
        
        curl_close($ch);
        
        if ($delay > 0) {
            sleep($delay);
        }
    }
    
    return $results;
}

$message = "";
$results = [];

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $url = $_POST["url"] ?? "";
    $delay = isset($_POST["delay"]) ? (int)$_POST["delay"] : 0;
    $proxy = !empty($_POST["proxy"]) ? $_POST["proxy"] : null;
    $wordlist = "list.txt"; // Default wordlist
    
    if (!empty($_FILES["wordlist"]["tmp_name"])) {
        $wordlist = $_FILES["wordlist"]["tmp_name"];
    }
    
    if (!empty($url)) {
        $results = scanUrl($url, $wordlist, $proxy, $delay);
        if (isset($results["error"])) {
            $message = $results["error"];
            $results = [];
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel Finder</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"],
        input[type="number"],
        input[type="file"] {
            width: 100%;
            padding: 8px;
            margin-bottom: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        button {
            background: #4CAF50;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover {
            background: #45a049;
        }
        .results {
            margin-top: 20px;
        }
        .result-item {
            padding: 10px;
            border-bottom: 1px solid #eee;
        }
        .result-item:last-child {
            border-bottom: none;
        }
        .error {
            color: red;
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Admin Panel Finder</h1>
        <p><strong>Note:</strong> This tool is for educational and testing purposes only.</p>
        
        <?php if ($message): ?>
            <div class="error"><?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>
        
        <form method="POST" enctype="multipart/form-data">
            <div class="form-group">
                <label for="url">Website URL:</label>
                <input type="text" id="url" name="url" placeholder="https://example.com" required>
            </div>
            
            <div class="form-group">
                <label for="delay">Delay (seconds):</label>
                <input type="number" id="delay" name="delay" min="0" value="0">
            </div>
            
            <div class="form-group">
                <label for="proxy">Proxy (optional):</label>
                <input type="text" id="proxy" name="proxy" placeholder="http://proxy:port">
            </div>
            
            <div class="form-group">
                <label for="wordlist">Custom Wordlist (optional):</label>
                <input type="file" id="wordlist" name="wordlist">
            </div>
            
            <button type="submit">Scan</button>
        </form>
        
        <?php if (!empty($results)): ?>
            <div class="results">
                <h2>Results:</h2>
                <?php foreach ($results as $result): ?>
                    <div class="result-item">
                        <strong>Found:</strong> 
                        <a href="<?php echo htmlspecialchars($result['url']); ?>" target="_blank">
                            <?php echo htmlspecialchars($result['path']); ?>
                        </a>
                        (Status: <?php echo htmlspecialchars($result['status']); ?>)
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>
