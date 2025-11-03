#!/usr/bin/php
<?php

defined('AF_INET')  || define('AF_INET', 2);
defined('AF_INET6') || define('AF_INET6', 10);
defined('JSON_INVALID_UTF8_SUBSTITUTE') || define('JSON_INVALID_UTF8_SUBSTITUTE', 0);
defined('SOCKET_READ_TIMEOUT') || define('SOCKET_READ_TIMEOUT', 5);

const IPV4_HEX_LENGTH = 8;
const IPV6_HEX_LENGTH = 32;
const MIN_PORT = 1;
const MAX_PORT = 65535;
const MIN_INTERVAL = 1;
const MAX_INTERVAL = 3600;
const MIN_CIDR_IPV4 = 0;
const MAX_CIDR_IPV4 = 32;
const MIN_CIDR_IPV6 = 0;
const MAX_CIDR_IPV6 = 128;
const MAX_CONNECTION_AGE = 3600;
const MAX_PROCESS_SCAN_TIME = 30;

const TCP_STATES = [
    '01' => "ESTABLISHED",
    '02' => "SYN_SENT", 
    '03' => "SYN_RECV",
    '04' => "FIN_WAIT1",
    '05' => "FIN_WAIT2",
    '06' => "TIME_WAIT",
    '07' => "CLOSE",
    '08' => "CLOSE_WAIT",
    '09' => "LAST_ACK",
    '0A' => "LISTEN",
    '0B' => "CLOSING",
    '0C' => "NEW_SYN_RECV",
];

const COLORS = [
    'LISTEN' => "\033[32m",
    'ESTABLISHED' => "\033[36m", 
    'TIME_WAIT' => "\033[33m",
    'CLOSE_WAIT' => "\033[31m",
    'FIN_WAIT1' => "\033[35m",
    'FIN_WAIT2' => "\033[35m",
    'SYN_RECV' => "\033[34m",
    'LAST_ACK' => "\033[31m",
    'CLOSING' => "\033[33m",
    'reset' => "\033[0m"
];

class Security {
    public static function sanitizeOutput($data) {
        if (!is_string($data)) return $data;
        return htmlspecialchars($data, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
    
    public static function validatePath($path): bool {
        $normalizedPath = self::normalizePath($path);
        
        if (strpos($normalizedPath, '/proc/') !== 0) {
            Logger::log("Path validation failed: $normalizedPath is not under /proc", 'DEBUG');
            return false;
        }
        
        $allowedPatterns = [
            '#^/proc/net/(tcp|tcp6|udp|udp6|raw|raw6|unix)$#',
            '#^/proc/\d+$#',
            '#^/proc/\d+/(comm|status|cmdline|exe|fd|net|fdinfo)$#',
            '#^/proc/\d+/fd/\d+$#',
            '#^/proc/version$#',
            '#^/proc/self$#'
        ];
        
        foreach ($allowedPatterns as $pattern) {
            if (preg_match($pattern, $normalizedPath)) {
                return true;
            }
        }
        
        Logger::log("Path validation failed: $normalizedPath does not match allowed patterns", 'DEBUG');
        return false;
    }
    
    private static function normalizePath(string $path): string {
        if (strpos($path, '/') !== 0) {
            $path = '/' . $path;
        }
        
        $parts = explode('/', $path);
        $result = [];
        
        foreach ($parts as $part) {
            if ($part === '' || $part === '.') continue;
            if ($part === '..') {
                if (!empty($result)) array_pop($result);
                continue;
            }
            $result[] = $part;
        }
        
        return '/' . implode('/', $result);
    }
    
    public static function validateProcFilesystem(): void {
        if (!file_exists('/proc') || !is_dir('/proc')) {
            throw new RuntimeException("/proc directory does not exist or is not accessible");
        }
        
        if (!file_exists('/proc/self') && !file_exists('/proc/version')) {
            throw new RuntimeException("/proc does not appear to be a valid proc filesystem");
        }
    }
}

class Config {
    private static $defaults = [
        'refresh_interval' => 2,
        'max_display_processes' => 10,
        'process_cache_ttl' => 5,
        'connection_cache_ttl' => 1,
        'colors_enabled' => true,
        'max_history' => 1000,
        'rate_limit_requests' => 100,
        'rate_limit_window' => 60,
        'max_cache_size' => 10000,
        'max_connections_per_scan' => 100000,
        'socket_read_timeout' => 5,
        'enable_process_scan' => true,
    ];
    
    public static function get(string $key, $default = null) {
        return $_ENV['TCP_MONITOR_' . strtoupper($key)] ?? self::$defaults[$key] ?? $default;
    }
    
    public static function set(string $key, $value): void {
        self::$defaults[$key] = $value;
    }
}

class RateLimiter {
    private static $requests = [];
    
    public static function checkLimit(): bool {
        $maxRequests = Config::get('rate_limit_requests', 100);
        $window = Config::get('rate_limit_window', 60);
        $now = time();
        
        self::$requests = array_filter(self::$requests, function($time) use ($now, $window) {
            return $time > $now - $window;
        });
        
        if (count(self::$requests) >= $maxRequests) {
            return false;
        }
        
        self::$requests[] = $now;
        return true;
    }
}

class PerformanceTracker {
    private static $startTime;
    private static $memoryPeak = 0;
    private static $operations = 0;
    private static $memoryChecks = [];
    private static $timers = [];

    public static function start(): void {
        self::$startTime = microtime(true);
        self::$memoryPeak = memory_get_peak_usage(true);
    }

    public static function recordOperation(string $type = 'general'): void {
        self::$operations++;
        self::checkMemoryUsage();
        
        if (!isset(self::$timers[$type])) {
            self::$timers[$type] = ['count' => 0, 'time' => 0];
        }
        self::$timers[$type]['count']++;
    }

    public static function startTimer(string $name): void {
        self::$timers[$name] = ['start' => microtime(true)];
    }

    public static function stopTimer(string $name): void {
        if (isset(self::$timers[$name]['start'])) {
            $duration = microtime(true) - self::$timers[$name]['start'];
            if (!isset(self::$timers[$name]['total'])) {
                self::$timers[$name]['total'] = 0;
                self::$timers[$name]['count'] = 0;
            }
            self::$timers[$name]['total'] += $duration;
            self::$timers[$name]['count']++;
            self::$timers[$name]['average'] = self::$timers[$name]['total'] / self::$timers[$name]['count'];
        }
    }

    public static function checkMemoryUsage(): void {
        $currentMemory = memory_get_usage(true);
        $peakMemory = memory_get_peak_usage(true);
        
        if ($peakMemory > self::$memoryPeak) {
            self::$memoryPeak = $peakMemory;
        }
        
        self::$memoryChecks[] = [
            'timestamp' => microtime(true),
            'current' => $currentMemory,
            'peak' => $peakMemory
        ];
        
        if (count(self::$memoryChecks) > 100) {
            array_shift(self::$memoryChecks);
        }
        
        if ($currentMemory > 512 * 1024 * 1024) {
            fwrite(STDERR, "Emergency shutdown: Memory usage too high\n");
            exit(1);
        }
    }

    public static function getMetrics(): array {
        $endTime = microtime(true);
        return [
            'execution_time' => round($endTime - self::$startTime, 4),
            'memory_peak_mb' => round(self::$memoryPeak / 1024 / 1024, 2),
            'operations' => self::$operations,
            'memory_checks' => count(self::$memoryChecks),
            'timers' => self::$timers,
            'timestamp' => date('c')
        ];
    }
}

class Logger {
    private static $logFile = null;
    private static $logLevel = 'INFO';
    private static $levels = ['DEBUG' => 0, 'INFO' => 1, 'WARNING' => 2, 'ERROR' => 3];
    
    public static function setLogLevel(string $level): void {
        if (isset(self::$levels[$level])) {
            self::$logLevel = $level;
        }
    }
    
    public static function log(string $message, string $level = 'INFO'): void {
        if (self::$levels[$level] < self::$levels[self::$logLevel]) {
            return;
        }
        
        $timestamp = date('Y-m-d H:i:s');
        $logEntry = "[$timestamp] [$level] $message\n";
        
        if (self::$logFile) {
            file_put_contents(self::$logFile, $logEntry, FILE_APPEND | LOCK_EX);
        } else {
            fwrite(STDERR, $logEntry);
        }
    }
    
    public static function setLogFile(string $file): void {
        if (!is_writable(dirname($file))) {
            throw new RuntimeException("Log directory is not writable: " . dirname($file));
        }
        self::$logFile = $file;
    }
}

class ErrorHandler {
    public static function handleFileRead(string $file): string {
        if (!Security::validatePath($file)) {
            throw new RuntimeException("Invalid file path: $file");
        }
        
        if (!file_exists($file)) {
            throw new RuntimeException("File $file does not exist");
        }
        
        if (!is_readable($file)) {
            throw new RuntimeException("File $file is not readable");
        }
        
        $content = @file_get_contents($file);
        if ($content === false) {
            $error = error_get_last();
            throw new RuntimeException("Failed to read $file: " . ($error['message'] ?? 'Unknown error'));
        }
        
        return $content;
    }
    
    public static function handle(Exception $e, bool $verbose = false): void {
        $message = "Error: " . Security::sanitizeOutput($e->getMessage());
        fwrite(STDERR, $message . "\n");
        Logger::log($message, 'ERROR');
        
        if ($verbose) {
            $details = "File: " . Security::sanitizeOutput($e->getFile()) . " Line: " . Security::sanitizeOutput($e->getLine());
            fwrite(STDERR, $details . "\n");
            Logger::log($details, 'DEBUG');
        }
    }
}

class InputValidator {
    public static function validatePort($port): int {
        if (!is_numeric($port) || $port < MIN_PORT || $port > MAX_PORT) {
            throw new InvalidArgumentException("Port must be between " . MIN_PORT . " and " . MAX_PORT);
        }
        return (int)$port;
    }
    
    public static function validateIpFilter(string $filter): string {
        if (!self::isValidIpOrCidr($filter)) {
            throw new InvalidArgumentException("Invalid IP or CIDR notation: $filter");
        }
        return $filter;
    }
    
    private static function isValidIpOrCidr(string $input): bool {
        if (strpos($input, '/') !== false) {
            list($ip, $mask) = explode('/', $input, 2);
            if (!is_numeric($mask)) return false;
            
            $mask = (int)$mask;
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                return $mask >= MIN_CIDR_IPV4 && $mask <= MAX_CIDR_IPV4;
            }
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                return $mask >= MIN_CIDR_IPV6 && $mask <= MAX_CIDR_IPV6;
            }
            return false;
        }
        
        return filter_var($input, FILTER_VALIDATE_IP) !== false;
    }
    
    public static function validateInterval($interval): int {
        if (!is_numeric($interval) || $interval < MIN_INTERVAL || $interval > MAX_INTERVAL) {
            throw new InvalidArgumentException("Interval must be between " . MIN_INTERVAL . " and " . MAX_INTERVAL . " seconds");
        }
        return (int)$interval;
    }
    
    public static function validateOutputFile(string $file): string {
        $dir = dirname($file);
        if (!is_writable($dir)) {
            throw new InvalidArgumentException("Output directory is not writable: $dir");
        }
        return $file;
    }
}

class ProcessCache {
    private static $cache = [];
    private static $lastBuild = 0;
    private static $processScanTime = [];
    private static $scanStartTime = 0;

    public static function getProcessMap(): array {
        $now = time();
        if (empty(self::$cache) || ($now - self::$lastBuild) > Config::get('process_cache_ttl')) {
            self::$cache = self::buildProcessMap();
            self::$lastBuild = $now;
            self::enforceCacheLimits();
        }
        return self::$cache;
    }

    private static function buildProcessMap(): array {
        if (!Config::get('enable_process_scan', true)) {
            return [];
        }
        
        Security::validateProcFilesystem();
        
        $processMap = [];
        $inodes = self::extractInodesFromProcNet();
        
        if (empty($inodes)) {
            Logger::log("No inodes found in /proc/net files");
            return $processMap;
        }

        self::$scanStartTime = time();
        $procDir = @opendir('/proc');
        if ($procDir === false) {
            throw new RuntimeException("Cannot open /proc directory");
        }

        try {
            while (($entry = readdir($procDir)) !== false) {
                if (!ctype_digit($entry)) continue;
                
                if ((time() - self::$scanStartTime) > MAX_PROCESS_SCAN_TIME) {
                    Logger::log("Process scan timeout after " . MAX_PROCESS_SCAN_TIME . " seconds", 'WARNING');
                    break;
                }

                $pid = (int)$entry;
                $processDir = "/proc/{$pid}";

                if (!is_dir($processDir)) continue;

                $foundInodes = self::scanProcessInodes($pid, $inodes);
                if (!empty($foundInodes)) {
                    $processName = self::getProcessName($pid);
                    foreach ($foundInodes as $inode) {
                        $processMap[$inode] = $processName;
                    }
                }
                
                PerformanceTracker::recordOperation('process_scan');
            }
        } finally {
            closedir($procDir);
        }
        
        Logger::log("Built process map with " . count($processMap) . " entries in " . (time() - self::$scanStartTime) . "s");
        return $processMap;
    }
    
    private static function extractInodesFromProcNet(): array {
        $inodes = [];
        $files = ['/proc/net/tcp', '/proc/net/tcp6', '/proc/net/udp', '/proc/net/udp6'];
        
        foreach ($files as $file) {
            if (!Security::validatePath($file)) {
                continue;
            }
            
            if (!file_exists($file)) continue;
            
            PerformanceTracker::startTimer("read_$file");
            $handle = @fopen($file, 'r');
            if ($handle === false) continue;
            
            try {
                $lineCount = 0;
                while (($line = fgets($handle)) !== false) {
                    $lineCount++;
                    if ($lineCount > Config::get('max_connections_per_scan', 100000)) {
                        Logger::log("Reached max connections limit for $file", 'WARNING');
                        break;
                    }
                    
                    if (preg_match('/\s+\d+:\s+[0-9A-F:]+\\s+[0-9A-F:]+\\s+[0-9A-F]+\\s+[0-9A-F]+\\s+[0-9A-F]+\\s+[0-9A-F]+\\s+[0-9A-F]+\\s+[0-9A-F]+\\s+(\d+)/', $line, $matches)) {
                        $inodes[$matches[1]] = true;
                    }
                    PerformanceTracker::recordOperation('inode_extraction');
                }
            } finally {
                fclose($handle);
                PerformanceTracker::stopTimer("read_$file");
            }
        }
        
        return $inodes;
    }
    
    private static function scanProcessInodes(int $pid, array $targetInodes): array {
        $foundInodes = [];
        $fdPath = "/proc/{$pid}/fd";
        
        if (!is_dir($fdPath)) return $foundInodes;

        $fdDir = @opendir($fdPath);
        if ($fdDir === false) return $foundInodes;

        try {
            while (($fd = readdir($fdDir)) !== false) {
                if ($fd === '.' || $fd === '..') continue;

                $link = @readlink($fdPath . '/' . $fd);
                if ($link && preg_match('/socket:\[(\d+)\]/', $link, $matches)) {
                    $inode = $matches[1];
                    if (isset($targetInodes[$inode])) {
                        $foundInodes[] = $inode;
                    }
                }
                PerformanceTracker::recordOperation('fd_scan');
            }
        } finally {
            closedir($fdDir);
        }
        
        return $foundInodes;
    }
    
    private static function getProcessName(int $pid): string {
        $commPath = "/proc/{$pid}/comm";
        $processName = @file_get_contents($commPath);
        return $processName ? trim($processName) . " (PID: $pid)" : "PID: $pid";
    }
    
    private static function enforceCacheLimits(): void {
        $maxSize = Config::get('max_cache_size', 10000);
        if (count(self::$cache) > $maxSize) {
            self::$cache = array_slice(self::$cache, -$maxSize, null, true);
            Logger::log("Process cache trimmed to $maxSize entries");
        }
    }
    
    public static function clearCache(): void {
        self::$cache = [];
        self::$lastBuild = 0;
        self::$processScanTime = [];
    }
    
    public static function disableProcessScan(): void {
        Config::set('enable_process_scan', false);
    }
}

class IPUtils {
    public static function hexToIpv4(string $hex): string {
        if (strlen($hex) !== IPV4_HEX_LENGTH) return '0.0.0.0';

        $parts = [];
        for ($i = 0; $i < IPV4_HEX_LENGTH; $i += 2) {
            $parts[] = hexdec(substr($hex, $i, 2));
        }

        return implode('.', array_reverse($parts));
    }

    public static function hexToIpv6(string $hex): string {
        $hex = preg_replace('/[^0-9A-Fa-f]/', '', $hex);
        if (strlen($hex) !== IPV6_HEX_LENGTH) return '::';

        $blocks = str_split($hex, 8);
        $blocks = array_reverse($blocks);
        $reordered = implode('', $blocks);
        $packed = pack('H*', $reordered);
        $addr = @inet_ntop($packed);
        return $addr ?: '::';
    }

    public static function ipInCidr(string $ip, string $cidr): bool {
        list($subnet, $mask) = explode('/', $cidr);
        $mask = (int)$mask;

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return self::ipv4InCidr($ip, $subnet, $mask);
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return self::ipv6InCidr($ip, $subnet, $mask);
        }

        return false;
    }

    private static function ipv4InCidr(string $ip, string $subnet, int $mask): bool {
        if ($mask === 0) return true;
        if ($mask >= 32) return $ip === $subnet;

        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);

        if ($ipLong === false || $subnetLong === false) return false;

        if (PHP_INT_SIZE === 4) {
            $maskLong = ($mask === 0) ? 0 : (0xFFFFFFFF << (32 - $mask));
            return (($ipLong & $maskLong) === ($subnetLong & $maskLong));
        } else {
            $maskLong = ($mask === 0) ? 0 : ((0xFFFFFFFF << (32 - $mask)) & 0xFFFFFFFF);
            return (($ipLong & $maskLong) === ($subnetLong & $maskLong));
        }
    }

    private static function ipv6InCidr(string $ip, string $subnet, int $mask): bool {
        $ipBin = inet_pton($ip);
        $subnetBin = inet_pton($subnet);

        if ($ipBin === false || $subnetBin === false) return false;
        if ($mask === 0) return true;

        $binMask = str_repeat('f', intval(floor($mask / 4)));
        if ($mask % 4) {
            $binMask .= dechex(15 << (4 - ($mask % 4)));
        }
        $binMask = str_pad($binMask, 32, '0');
        $binMask = pack('H*', $binMask);
        
        return ($ipBin & $binMask) === ($subnetBin & $binMask);
    }
}

class ConnectionCache {
    private static $cache = [];
    
    public static function getConnections(string $file, int $family, bool $includeProcess = false): array {
        $key = $file . '_' . $family . '_' . (int)$includeProcess;
        
        $fileHash = self::getFileHash($file);
        if ($fileHash === null) return [];
        
        $cacheKey = $key . '_' . $fileHash;
        
        if (!isset(self::$cache[$cacheKey]) || (time() - self::$cache[$cacheKey]['timestamp']) > Config::get('connection_cache_ttl')) {
            PerformanceTracker::startTimer("read_connections_$family");
            self::$cache[$cacheKey] = [
                'data' => self::readConnections($file, $family, $includeProcess),
                'timestamp' => time()
            ];
            PerformanceTracker::stopTimer("read_connections_$family");
            self::cleanupOldCache();
        }
        
        return self::$cache[$cacheKey]['data'];
    }
    
    private static function getFileHash(string $file): ?string {
        if (!Security::validatePath($file)) {
            return null;
        }
        
        if (!file_exists($file) || !is_readable($file)) {
            return null;
        }
        
        $content = @file_get_contents($file);
        if ($content === false) {
            return null;
        }
        
        return md5($content);
    }
    
    private static function readConnections(string $file, int $family, bool $includeProcess): array {
        if (!Security::validatePath($file)) {
            throw new RuntimeException("Invalid file path: $file");
        }

        if (!file_exists($file)) return [];
        if (!is_readable($file)) return [];

        $handle = @fopen($file, 'r');
        if ($handle === false) {
            return [];
        }

        $processMap = $includeProcess ? ProcessCache::getProcessMap() : null;

        fgets($handle);

        $connections = [];
        $lineCount = 0;
        try {
            while (($line = fgets($handle)) !== false) {
                $lineCount++;
                if ($lineCount > Config::get('max_connections_per_scan', 100000)) {
                    Logger::log("Reached max connections limit for $file", 'WARNING');
                    break;
                }
                
                PerformanceTracker::recordOperation('connection_parse');
                $line = trim($line);
                if (empty($line)) continue;

                $fields = preg_split('/\s+/', $line);
                if (count($fields) < 10) continue;

                $connection = self::parseConnectionLine($fields, $family, $processMap);
                if ($connection) $connections[] = $connection;
            }
        } finally {
            fclose($handle);
        }
        
        return $connections;
    }
    
    private static function parseConnectionLine(array $fields, int $family, ?array $processMap): ?array {
        list($localIpHex, $localPortHex) = explode(':', $fields[1], 2);
        list($remoteIpHex, $remotePortHex) = explode(':', $fields[2], 2);

        if ($family === AF_INET) {
            $localIp = IPUtils::hexToIpv4($localIpHex);
            $remoteIp = IPUtils::hexToIpv4($remoteIpHex);
        } else {
            $localIp = IPUtils::hexToIpv6($localIpHex);
            $remoteIp = IPUtils::hexToIpv6($remoteIpHex);
        }

        $localPort = hexdec($localPortHex);
        $remotePort = hexdec($remotePortHex);
        $stateCode = strtoupper($fields[3]);
        $state = TCP_STATES[$stateCode] ?? "UNKNOWN(0x$stateCode)";
        $proto = ($family === AF_INET) ? 'IPv4' : 'IPv6';
        $inode = $fields[9];
        $process = $processMap ? self::getProcessByInode($inode, $processMap) : '';

        return [
            'proto'       => $proto,
            'state'       => $state,
            'local_ip'    => $localIp,
            'local_port'  => $localPort,
            'remote_ip'   => $remoteIp,
            'remote_port' => $remotePort,
            'inode'       => $inode,
            'process'     => $process,
            'timestamp'   => time()
        ];
    }
    
    private static function getProcessByInode($inode, array $processMap): string {
        static $processCache = [];
        
        if (isset($processCache[$inode])) return $processCache[$inode];
        if (isset($processMap[$inode])) {
            $processCache[$inode] = $processMap[$inode];
            return $processMap[$inode];
        }

        $processCache[$inode] = "";
        return "";
    }
    
    private static function cleanupOldCache(): void {
        $now = time();
        $ttl = Config::get('connection_cache_ttl', 1);
        $maxSize = Config::get('max_cache_size', 10000);
        
        foreach (self::$cache as $key => $data) {
            if ($now - $data['timestamp'] > $ttl * 2) {
                unset(self::$cache[$key]);
            }
        }
        
        if (count(self::$cache) > $maxSize) {
            self::$cache = array_slice(self::$cache, -$maxSize, null, true);
        }
    }
    
    public static function clearCache(): void {
        self::$cache = [];
    }
}

class OutputFormatter {
    public static function formatTable(array $connections, bool $showProcess = false): string {
        if (empty($connections)) return "No connections found.\n";

        self::sortConnections($connections);
        $output = "\nACTIVE TCP CONNECTIONS:\n";

        if ($showProcess) {
            $output .= sprintf("%-5s %-15s %-25s %-25s %-30s\n", "Proto", "State", "Local Address", "Remote Address", "Process");
            $output .= str_repeat("-", 105) . "\n";
            foreach ($connections as $c) {
                $color = self::getStateColor($c['state']);
                $reset = COLORS['reset'];
                $process = $c['process'] ?: 'unknown';
                $output .= sprintf(
                    "%-5s {$color}%-15s{$reset} %-25s %-25s %-30s\n",
                    $c['proto'],
                    $c['state'],
                    "{$c['local_ip']}:{$c['local_port']}",
                    "{$c['remote_ip']}:{$c['remote_port']}",
                    substr($process, 0, 30)
                );
            }
        } else {
            $output .= sprintf("%-5s %-15s %-25s %-25s\n", "Proto", "State", "Local Address", "Remote Address");
            $output .= str_repeat("-", 75) . "\n";
            foreach ($connections as $c) {
                $color = self::getStateColor($c['state']);
                $reset = COLORS['reset'];
                $output .= sprintf(
                    "%-5s {$color}%-15s{$reset} %-25s %-25s\n",
                    $c['proto'],
                    $c['state'],
                    "{$c['local_ip']}:{$c['local_port']}",
                    "{$c['remote_ip']}:{$c['remote_port']}"
                );
            }
        }

        $stats = self::getConnectionStats($connections);
        $output .= self::formatSummary($stats);
        return $output;
    }

    public static function formatJson(array $connections, bool $includeStats = false): string {
        if ($includeStats) {
            $output = [
                'connections' => $connections,
                'statistics' => self::getConnectionStats($connections),
                'metadata' => [
                    'generated_at' => date('c'),
                    'count' => count($connections)
                ]
            ];
        } else {
            $output = $connections;
        }

        return json_encode($output, JSON_PRETTY_PRINT | JSON_INVALID_UTF8_SUBSTITUTE) . "\n";
    }

    public static function formatCsv(array $connections): string {
        if (empty($connections)) return "";
        $output = "Protocol,State,Local IP,Local Port,Remote IP,Remote Port,Process,Inode\n";
        
        foreach ($connections as $conn) {
            $output .= sprintf(
                "%s,%s,%s,%d,%s,%d,%s,%s\n",
                $conn['proto'],
                $conn['state'],
                $conn['local_ip'],
                $conn['local_port'],
                $conn['remote_ip'],
                $conn['remote_port'],
                self::escapeCsvField($conn['process']),
                $conn['inode']
            );
        }
        
        return $output;
    }

    public static function formatStatistics(array $connections): string {
        $stats = self::getConnectionStats($connections);
        $output = "\nDETAILED TCP CONNECTION STATISTICS\n";
        $output .= str_repeat("=", 50) . "\n";
        $output .= "Generated at: " . $stats['timestamp'] . "\n";
        $output .= "Total connections: " . $stats['total'] . "\n";
        $output .= "IPv4 connections: " . $stats['ipv4'] . "\n";
        $output .= "IPv6 connections: " . $stats['ipv6'] . "\n\n";

        $output .= "Connections by State:\n";
        $output .= str_repeat("-", 30) . "\n";
        foreach ($stats['by_state'] as $state => $count) {
            $color = self::getStateColor($state);
            $reset = COLORS['reset'];
            $output .= sprintf("{$color}%-20s{$reset}: %d\n", $state, $count);
        }

        if (!empty($stats['by_process'])) {
            $output .= "\nConnections by Process (Top 10):\n";
            $output .= str_repeat("-", 50) . "\n";

            uasort($stats['by_process'], function($a, $b) {
                return $b <=> $a;
            });

            $count = 0;
            foreach ($stats['by_process'] as $process => $connCount) {
                if (empty($process)) continue;
                $output .= sprintf("%-40s: %d\n", $process, $connCount);
                if (++$count >= 10) break;
            }
        }
        
        return $output;
    }

    public static function getConnectionStats(array $connections): array {
        $stats = [
            'total' => count($connections),
            'ipv4' => 0,
            'ipv6' => 0,
            'by_state' => [],
            'by_process' => [],
            'timestamp' => date('c')
        ];

        foreach ($connections as $conn) {
            if ($conn['proto'] === 'IPv4') {
                $stats['ipv4']++;
            } else {
                $stats['ipv6']++;
            }

            $stats['by_state'][$conn['state']] = ($stats['by_state'][$conn['state']] ?? 0) + 1;

            if (!empty($conn['process'])) {
                $stats['by_process'][$conn['process']] = ($stats['by_process'][$conn['process']] ?? 0) + 1;
            }
        }

        return $stats;
    }

    private static function sortConnections(array &$connections): void {
        usort($connections, function ($a, $b) {
            return $a['local_port'] <=> $b['local_port'] ?:
                   strcmp($a['proto'], $b['proto']);
        });
    }

    private static function getStateColor(string $state): string {
        return COLORS[$state] ?? "\033[37m";
    }

    private static function formatSummary(array $stats): string {
        $output = "\nSummary: " . $stats['total'] . " total connections ({$stats['ipv4']} IPv4, {$stats['ipv6']} IPv6)\n";

        if (!empty($stats['by_state'])) {
            $output .= "By state: ";
            $stateStrings = [];
            foreach ($stats['by_state'] as $state => $count) {
                $color = self::getStateColor($state);
                $reset = COLORS['reset'];
                $stateStrings[] = "{$color}{$state}{$reset}: $count";
            }
            $output .= implode(", ", $stateStrings) . "\n";
        }
        
        return $output;
    }

    private static function escapeCsvField(string $field): string {
        if (strpos($field, ',') !== false || strpos($field, '"') !== false || strpos($field, "\n") !== false) {
            return '"' . str_replace('"', '""', $field) . '"';
        }
        return $field;
    }
}

class ConnectionFilter {
    public static function filter(array $connections, array $options): array {
        $filtered = $connections;

        $states = self::getRequestedStates($options);
        if ($states) {
            $filtered = array_filter($filtered, fn($c) => in_array($c['state'], $states, true));
        }

        if (isset($options['port'])) {
            $port = InputValidator::validatePort($options['port']);
            $filtered = array_filter($filtered, fn($c) =>
                $c['local_port'] === $port || $c['remote_port'] === $port);
        }

        if (isset($options['local-ip'])) {
            $localIp = InputValidator::validateIpFilter($options['local-ip']);
            $filtered = array_filter($filtered, fn($c) =>
                self::ipMatchesFilter($c['local_ip'], $localIp));
        }

        if (isset($options['remote-ip'])) {
            $remoteIp = InputValidator::validateIpFilter($options['remote-ip']);
            $filtered = array_filter($filtered, fn($c) =>
                self::ipMatchesFilter($c['remote_ip'], $remoteIp));
        }

        if (isset($options['ipv4'])) {
            $filtered = array_filter($filtered, fn($c) => $c['proto'] === 'IPv4');
        }

        if (isset($options['ipv6'])) {
            $filtered = array_filter($filtered, fn($c) => $c['proto'] === 'IPv6');
        }

        return array_values($filtered);
    }

    private static function getRequestedStates(array $options): array {
        $states = [];
        if (isset($options['listen'])) $states[] = 'LISTEN';
        if (isset($options['established'])) $states[] = 'ESTABLISHED';
        if (isset($options['timewait'])) $states[] = 'TIME_WAIT';
        if (isset($options['closewait'])) $states[] = 'CLOSE_WAIT';
        if (isset($options['finwait'])) {
            $states[] = 'FIN_WAIT1';
            $states[] = 'FIN_WAIT2';
        }
        return $states;
    }

    private static function ipMatchesFilter(string $ip, string $filter): bool {
        if ($ip === $filter) return true;
        if (strpos($filter, '/') !== false) return IPUtils::ipInCidr($ip, $filter);
        return false;
    }
}

class ConnectionHistory {
    private static $history = [];

    public static function trackChanges(array $current): array {
        $changes = [
            'timestamp' => time(),
            'total' => count($current),
            'added' => [],
            'removed' => []
        ];

        if (!empty(self::$history)) {
            $previous = end(self::$history);
            $currentKeys = array_map('self::getConnectionKey', $current);
            $previousKeys = array_map('self::getConnectionKey', $previous['connections']);
            
            $changes['added'] = array_diff($currentKeys, $previousKeys);
            $changes['removed'] = array_diff($previousKeys, $currentKeys);
        }

        self::$history[] = ['connections' => $current, 'changes' => $changes];
        if (count(self::$history) > Config::get('max_history')) {
            array_shift(self::$history);
        }

        return $changes;
    }

    private static function getConnectionKey(array $conn): string {
        return "{$conn['local_ip']}:{$conn['local_port']}-{$conn['remote_ip']}:{$conn['remote_port']}-{$conn['state']}";
    }
    
    public static function clearHistory(): void {
        self::$history = [];
    }
    
    public static function getHistoryStats(): array {
        return [
            'history_size' => count(self::$history),
            'total_tracked' => array_sum(array_map(fn($h) => count($h['connections']), self::$history))
        ];
    }
}

class SignalHandler {
    private static $shouldExit = false;
    private static $startTime;

    public static function init(): void {
        self::$startTime = time();

        if (function_exists('pcntl_signal')) {
            pcntl_signal(SIGINT, [self::class, 'handleSignal']);
            pcntl_signal(SIGTERM, [self::class, 'handleSignal']);
            pcntl_signal(SIGHUP, [self::class, 'handleSignal']);
            pcntl_signal(SIGUSR1, [self::class, 'handleSignal']);
        }
    }

    public static function handleSignal(int $signo): void {
        switch ($signo) {
            case SIGINT:
            case SIGTERM:
                self::$shouldExit = true;
                $duration = time() - self::$startTime;
                echo "\n\nMonitoring stopped after {$duration} seconds.\n";
                Logger::log("Received signal $signo, shutting down after $duration seconds");
                exit(0);
            case SIGHUP:
                Logger::log("Received SIGHUP, reloading configuration");
                break;
            case SIGUSR1:
                $metrics = PerformanceTracker::getMetrics();
                Logger::log("Debug signal received - Metrics: " . json_encode($metrics));
                break;
        }
    }

    public static function shouldExit(): bool {
        if (function_exists('pcntl_signal_dispatch')) {
            pcntl_signal_dispatch();
        }
        return self::$shouldExit;
    }
}

class TCPConnectionMonitor {
    private $options;
    
    public function __construct(array $options = []) {
        $this->options = $options;
    }
    
    public function getConnections(): array {
        if (!RateLimiter::checkLimit()) {
            $current = RateLimiter::getCurrentCount();
            $max = Config::get('rate_limit_requests', 100);
            throw new RuntimeException("Rate limit exceeded ($current/$max requests per minute)");
        }

        $includeProcess = isset($this->options['processes']);

        $connections = array_merge(
            ConnectionCache::getConnections('/proc/net/tcp', AF_INET, $includeProcess),
            ConnectionCache::getConnections('/proc/net/tcp6', AF_INET6, $includeProcess)
        );

        return ConnectionFilter::filter($connections, $this->options);
    }
    
    public function getStatistics(): array {
        $connections = $this->getConnections();
        return [
            'connections' => $connections,
            'stats' => OutputFormatter::getConnectionStats($connections)
        ];
    }
}

class ConnectionWatcher {
    private $monitor;
    
    public function __construct(TCPConnectionMonitor $monitor) {
        $this->monitor = $monitor;
    }
    
    public function watch(array $options, int $interval = 2): void {
        $lastConnections = [];
        $iteration = 0;

        SignalHandler::init();

        echo "Watching TCP connections (refresh every {$interval}s). Press Ctrl+C to stop.\n";
        echo "Started at: " . date('Y-m-d H:i:s') . "\n\n";

        while (!SignalHandler::shouldExit()) {
            $iteration++;
            echo "\033[2J\033[;H";

            $connections = $this->monitor->getConnections();
            $currentCount = count($connections);

            $changes = ConnectionHistory::trackChanges($connections);
            $this::displayChanges($changes, $iteration);

            echo "[" . date('H:i:s') . "] Iteration: $iteration | Connections: $currentCount\n";
            echo str_repeat("-", 60) . "\n";

            if (isset($options['json'])) {
                echo OutputFormatter::formatJson($connections, $options['stats'] ?? false);
            } else {
                echo OutputFormatter::formatTable($connections, $options['processes'] ?? false);
            }

            $lastConnections = $connections;

            $slept = 0;
            while ($slept < $interval && !SignalHandler::shouldExit()) {
                sleep(1);
                $slept++;
            }

            if (SignalHandler::shouldExit()) break;
        }
    }
    
    private static function displayChanges(array $changes, int $iteration): void {
        if ($iteration === 1) return;

        $totalChanges = count($changes['added']) + count($changes['removed']);
        if ($totalChanges === 0) {
            echo "No changes since last refresh\n";
            return;
        }

        echo "Changes: \033[32m+" . count($changes['added']) . "\033[0m \033[31m-" . count($changes['removed']) . "\033[0m\n";

        if (!empty($changes['added'])) {
            echo "\033[32mNew connections:\033[0m\n";
            foreach (array_slice($changes['added'], 0, 3) as $key) {
                echo "  + $key\n";
            }
            if (count($changes['added']) > 3) {
                echo "  ... and " . (count($changes['added']) - 3) . " more\n";
            }
        }

        if (!empty($changes['removed'])) {
            echo "\033[31mClosed connections:\033[0m\n";
            foreach (array_slice($changes['removed'], 0, 3) as $key) {
                echo "  - $key\n";
            }
            if (count($changes['removed']) > 3) {
                echo "  ... and " . (count($changes['removed']) - 3) . " more\n";
            }
        }

        echo "\n";
    }
}

class OptionParser {
    public static function parse(array $argv): array {
        $script = basename($argv[0] ?? 'tcp_monitor.php');
        
        $options = getopt("jlpv", [
            "json", "help", "listen", "established", "count", "processes",
            "timewait", "closewait", "finwait", "port:", "watch::",
            "local-ip:", "remote-ip:", "stats", "ipv4", "ipv6", "verbose",
            "csv", "output:", "log-file:", "no-processes", "debug"
        ]);

        if (isset($options['help'])) {
            self::displayHelp($script);
            exit(0);
        }
        
        self::validateOptions($options);
        return $options;
    }
    
    private static function validateOptions(array &$options): void {
        if (isset($options['port'])) {
            $options['port'] = InputValidator::validatePort($options['port']);
        }
        
        if (isset($options['watch']) && $options['watch'] !== false) {
            $interval = $options['watch'] === false ? 2 : $options['watch'];
            $options['watch_interval'] = InputValidator::validateInterval($interval);
        }
        
        if (isset($options['local-ip'])) {
            $options['local-ip'] = InputValidator::validateIpFilter($options['local-ip']);
        }
        
        if (isset($options['remote-ip'])) {
            $options['remote-ip'] = InputValidator::validateIpFilter($options['remote-ip']);
        }
        
        if (isset($options['output'])) {
            $options['output'] = InputValidator::validateOutputFile($options['output']);
        }
        
        if (isset($options['log-file'])) {
            Logger::setLogFile($options['log-file']);
        }
        
        if (isset($options['debug'])) {
            Logger::setLogLevel('DEBUG');
        }
        
        if (isset($options['no-processes'])) {
            ProcessCache::disableProcessScan();
        }
    }
    
    private static function displayHelp(string $script): void {
        echo "Usage: php {$script} [options]\n";
        echo "Options:\n";
        echo "  --json         Output connections in JSON format\n";
        echo "  --csv          Output connections in CSV format\n";
        echo "  --listen       Show only listening sockets\n";
        echo "  --established  Show only established connections\n";
        echo "  --timewait     Show only TIME_WAIT connections\n";
        echo "  --closewait    Show only CLOSE_WAIT connections\n";
        echo "  --finwait      Show only FIN_WAIT1/FIN_WAIT2 connections\n";
        echo "  --count        Only show counts (IPv4/IPv6/total)\n";
        echo "  --processes    Show process information (slower)\n";
        echo "  --no-processes Disable process scanning (faster)\n";
        echo "  --port <num>   Filter by port number\n";
        echo "  --local-ip <ip>  Filter by local IP address (supports CIDR)\n";
        echo "  --remote-ip <ip> Filter by remote IP address (supports CIDR)\n";
        echo "  --ipv4         Show only IPv4 connections\n";
        echo "  --ipv6         Show only IPv6 connections\n";
        echo "  --watch [sec]  Refresh continuously (default: 2s)\n";
        echo "  --stats        Show detailed statistics\n";
        echo "  --output <file>  Write output to file\n";
        echo "  --log-file <file> Write logs to file\n";
        echo "  --verbose, -v  Show performance metrics\n";
        echo "  --debug        Enable debug logging\n";
        echo "  --help         Show this help message\n";
    }
}

class Exporter {
    public static function toFile(string $content, string $filename): void {
        $result = file_put_contents($filename, $content, LOCK_EX);
        if ($result === false) {
            throw new RuntimeException("Failed to write to file: $filename");
        }
        echo "Output written to: $filename\n";
        Logger::log("Output written to: $filename");
    }
}

class Application {
    public static function run(): void {
        try {
            PerformanceTracker::start();

            if (php_sapi_name() !== 'cli') {
                throw new RuntimeException("This script must be run from the command line.");
            }

            if (!stristr(PHP_OS, 'Linux')) {
                throw new RuntimeException("This script is only supported on Linux systems.");
            }

            Security::validateProcFilesystem();

            if (function_exists('posix_geteuid') && posix_geteuid() !== 0) {
                fwrite(STDERR, "Note: Some information may be limited without root privileges.\n");
                Logger::log("Running without root privileges - some information may be limited");
            }

            $options = OptionParser::parse($_SERVER['argv']);
            
            $monitor = new TCPConnectionMonitor($options);

            if (isset($options['watch'])) {
                $watcher = new ConnectionWatcher($monitor);
                $interval = $options['watch_interval'] ?? 2;
                $watcher->watch($options, $interval);
                exit(0);
            }

            $connections = $monitor->getConnections();

            if (empty($connections)) {
                echo "No matching TCP connections found.\n";
                self::displayPerformanceMetrics($options);
                exit(0);
            }

            $output = '';
            if (isset($options['count'])) {
                $stats = OutputFormatter::getConnectionStats($connections);
                echo "Counts: total=" . $stats['total'] . " IPv4={$stats['ipv4']} IPv6={$stats['ipv6']}\n";
                exit(0);
            }

            if (isset($options['stats'])) {
                $output = OutputFormatter::formatStatistics($connections);
            } elseif (isset($options['j']) || isset($options['json'])) {
                $output = OutputFormatter::formatJson($connections, $options['stats'] ?? false);
            } elseif (isset($options['csv'])) {
                $output = OutputFormatter::formatCsv($connections);
            } else {
                $output = OutputFormatter::formatTable($connections, $options['processes'] ?? false);
            }

            if (isset($options['output'])) {
                Exporter::toFile($output, $options['output']);
            } else {
                echo $output;
            }

            self::displayPerformanceMetrics($options);

        } catch (Exception $e) {
            ErrorHandler::handle($e, $options['verbose'] ?? false);
            exit(1);
        }
    }

    private static function displayPerformanceMetrics(array $options): void {
        if (isset($options['verbose']) || isset($options['v']) || isset($options['debug'])) {
            $metrics = PerformanceTracker::getMetrics();
            echo "\nPerformance Metrics:\n";
            echo "Execution time: {$metrics['execution_time']}s\n";
            echo "Memory peak: {$metrics['memory_peak_mb']} MB\n";
            echo "Operations: {$metrics['operations']}\n";
            
            if (!empty($metrics['timers'])) {
                echo "\nTimers:\n";
                foreach ($metrics['timers'] as $name => $timer) {
                    if (isset($timer['total'])) {
                        echo "  $name: {$timer['total']}s total, {$timer['count']} calls, {$timer['average']}s avg\n";
                    }
                }
            }
        }
    }
}

register_shutdown_function(function() {
    $error = error_get_last();
    if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
        $message = "Fatal error: {$error['message']} in {$error['file']} on line {$error['line']}";
        fwrite(STDERR, $message . "\n");
        Logger::log($message, 'FATAL');
    }
    
    ProcessCache::clearCache();
    ConnectionCache::clearCache();
    ConnectionHistory::clearHistory();
});

Application::run();
