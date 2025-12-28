#!/usr/bin/php
<?php

declare(strict_types=1);

if (!defined('AF_INET')) define('AF_INET', 2);
if (!defined('AF_INET6')) define('AF_INET6', 10);
if (!defined('SOCKET_READ_TIMEOUT')) define('SOCKET_READ_TIMEOUT', 5);
if (!defined('JSON_INVALID_UTF8_SUBSTITUTE')) define('JSON_INVALID_UTF8_SUBSTITUTE', 128);

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
const MAX_FILE_SIZE = 10485760;
const MEMORY_WARNING_THRESHOLD = 256 * 1024 * 1024;
const MEMORY_CRITICAL_THRESHOLD = 384 * 1024 * 1024;
const MAX_PID = 4194304;
const MAX_CACHE_ENTRIES = 10000;

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

final class Security {
    public static function sanitizeOutput($data): string {
        if (!is_string($data)) {
            return (string)$data;
        }
        return htmlspecialchars($data, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }
    
    public static function validatePath(string $path): bool {
        $normalizedPath = self::normalizePath($path);
        
        if (!str_starts_with($normalizedPath, '/proc/')) {
            Logger::debug("Path validation failed: $normalizedPath is not under /proc");
            return false;
        }
        
        if (str_contains($normalizedPath, '..')) {
            Logger::debug("Path validation failed: $normalizedPath contains parent directory reference");
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
        
        Logger::debug("Path validation failed: $normalizedPath does not match allowed patterns");
        return false;
    }
    
    private static function normalizePath(string $path): string {
        $path = trim($path);
        if ($path === '') {
            return '/';
        }
        
        if ($path[0] !== '/') {
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
        if (!is_dir('/proc')) {
            throw new RuntimeException("/proc directory does not exist or is not accessible");
        }
        
        if (!is_readable('/proc/self') && !is_readable('/proc/version')) {
            throw new RuntimeException("/proc does not appear to be a valid proc filesystem");
        }
    }
    
    public static function validateInteger($value, ?int $min = null, ?int $max = null): int {
        if (!is_numeric($value)) {
            throw new InvalidArgumentException("Value must be numeric");
        }
        
        $intVal = (int)$value;
        if ($min !== null && $intVal < $min) {
            throw new InvalidArgumentException("Value must be at least $min");
        }
        if ($max !== null && $intVal > $max) {
            throw new InvalidArgumentException("Value must be at most $max");
        }
        
        return $intVal;
    }
    
    public static function validatePid(int $pid): bool {
        return $pid > 0 && $pid <= MAX_PID;
    }
    
    public static function createTempFile(string $prefix, string $directory = null): string {
        $directory = $directory ?: sys_get_temp_dir();
        $tempFile = tempnam($directory, $prefix);
        if ($tempFile === false) {
            throw new RuntimeException("Failed to create temporary file");
        }
        return $tempFile;
    }
}

final class Config {
    private static array $config = [];
    private static array $defaults = [
        'refresh_interval' => 2,
        'max_display_processes' => 10,
        'process_cache_ttl' => 5,
        'connection_cache_ttl' => 1,
        'colors_enabled' => true,
        'max_history' => 1000,
        'rate_limit_requests' => 100,
        'rate_limit_window' => 60,
        'max_cache_size' => 10000,
        'max_connections_per_scan' => 50000,
        'socket_read_timeout' => 5,
        'enable_process_scan' => true,
        'log_level' => 'INFO',
    ];
    
    public static function get(string $key, $default = null) {
        $envKey = 'TCP_MONITOR_' . strtoupper($key);
        
        if (isset($_ENV[$envKey])) {
            return self::castValue($_ENV[$envKey], $key);
        }
        
        return self::$config[$key] ?? self::$defaults[$key] ?? $default;
    }
    
    public static function set(string $key, $value): void {
        if (isset(self::$defaults[$key])) {
            $value = self::castValue($value, $key);
        }
        self::$config[$key] = $value;
    }
    
    private static function castValue($value, string $key) {
        if (!isset(self::$defaults[$key])) {
            return $value;
        }
        
        $default = self::$defaults[$key];
        $type = gettype($default);
        
        switch ($type) {
            case 'integer':
                return (int)$value;
            case 'boolean':
                return filter_var($value, FILTER_VALIDATE_BOOLEAN);
            case 'double':
                return (float)$value;
            case 'string':
                return (string)$value;
            default:
                return $value;
        }
    }
    
    public static function loadFromFile(string $file): void {
        if (!is_file($file) || !is_readable($file)) {
            throw new RuntimeException("Config file not found or not readable: $file");
        }
        
        $content = file_get_contents($file);
        if ($content === false) {
            throw new RuntimeException("Cannot read config file: $file");
        }
        
        $config = json_decode($content, true, 512, JSON_THROW_ON_ERROR);
        
        if (!is_array($config)) {
            throw new RuntimeException("Invalid JSON structure in config file");
        }
        
        self::$config = array_merge(self::$defaults, $config);
    }
    
    public static function loadFromEnv(): void {
        foreach ($_ENV as $key => $value) {
            if (str_starts_with($key, 'TCP_MONITOR_')) {
                $configKey = strtolower(substr($key, 12));
                self::set($configKey, $value);
            }
        }
    }
    
    public static function loadFromEnvFile(string $file): void {
        if (!is_file($file) || !is_readable($file)) {
            throw new RuntimeException("Environment file not found: $file");
        }
        
        $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') continue;
            
            if (str_contains($line, '=')) {
                list($key, $value) = explode('=', $line, 2);
                $key = trim($key);
                $value = trim($value);
                
                if (str_starts_with($key, 'TCP_MONITOR_')) {
                    $_ENV[$key] = $value;
                }
            }
        }
    }
}

final class RateLimiter {
    private static array $requests = [];
    private static int $lastCleanup = 0;
    
    public static function checkLimit(): bool {
        $maxRequests = Config::get('rate_limit_requests', 100);
        $window = Config::get('rate_limit_window', 60);
        $now = time();
        
        if ($now - self::$lastCleanup > 5) {
            self::cleanupOldRequests($now, $window);
            self::$lastCleanup = $now;
        }
        
        if (count(self::$requests) >= $maxRequests) {
            return false;
        }
        
        self::$requests[] = $now;
        return true;
    }
    
    private static function cleanupOldRequests(int $now, int $window): void {
        self::$requests = array_filter(self::$requests, fn($time) => $time > $now - $window);
    }
    
    public static function getCurrentCount(): int {
        return count(self::$requests);
    }
}

final class PerformanceTracker {
    private static float $startTime;
    private static int $memoryPeak = 0;
    private static int $operations = 0;
    private static array $memoryChecks = [];
    private static array $timers = [];
    private static bool $gcTriggered = false;
    private static int $lastCheck = 0;

    public static function start(): void {
        self::$startTime = microtime(true);
        self::$memoryPeak = memory_get_peak_usage(true);
        self::$lastCheck = time();
    }

    public static function recordOperation(string $type = 'general'): void {
        self::$operations++;
        
        $now = time();
        if ($now - self::$lastCheck >= 1) {
            self::checkMemoryUsage();
            self::$lastCheck = $now;
        }
        
        if (!isset(self::$timers[$type])) {
            self::$timers[$type] = ['count' => 0, 'time' => 0.0];
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
                self::$timers[$name]['total'] = 0.0;
                self::$timers[$name]['count'] = 0;
            }
            self::$timers[$type]['total'] += $duration;
            self::$timers[$type]['count']++;
        }
    }

    public static function checkMemoryUsage(): void {
        $currentMemory = memory_get_usage(true);
        $peakMemory = memory_get_peak_usage(true);
        
        if ($peakMemory > self::$memoryPeak) {
            self::$memoryPeak = $peakMemory;
        }
        
        if ($currentMemory > MEMORY_CRITICAL_THRESHOLD && !self::$gcTriggered) {
            Logger::error("Critical memory usage: " . round($currentMemory/1024/1024, 2) . "MB");
            gc_collect_cycles();
            self::$gcTriggered = true;
        } elseif ($currentMemory > MEMORY_WARNING_THRESHOLD && !self::$gcTriggered) {
            Logger::warning("High memory usage: " . round($currentMemory/1024/1024, 2) . "MB");
        } elseif ($currentMemory <= MEMORY_WARNING_THRESHOLD) {
            self::$gcTriggered = false;
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
            Logger::fatal("Emergency shutdown due to memory usage: " . round($currentMemory/1024/1024, 2) . "MB");
            fwrite(STDERR, "Emergency shutdown: Memory usage too high\n");
            exit(1);
        }
    }

    public static function getMetrics(): array {
        $endTime = microtime(true);
        $metrics = [
            'execution_time' => round($endTime - self::$startTime, 4),
            'memory_peak_mb' => round(self::$memoryPeak / 1024 / 1024, 2),
            'operations' => self::$operations,
            'memory_checks' => count(self::$memoryChecks),
            'timestamp' => date('c')
        ];
        
        foreach (self::$timers as $name => $timer) {
            if (isset($timer['total'])) {
                $metrics['timers'][$name] = [
                    'total' => round($timer['total'], 4),
                    'count' => $timer['count'],
                    'average' => round($timer['total'] / $timer['count'], 4)
                ];
            }
        }
        
        return $metrics;
    }
    
    public static function reset(): void {
        self::$startTime = microtime(true);
        self::$operations = 0;
        self::$memoryChecks = [];
        self::$timers = [];
        self::$gcTriggered = false;
        self::$lastCheck = time();
    }
}

final class Logger {
    private static ?string $logFile = null;
    private static string $logLevel = 'INFO';
    private static array $levels = ['DEBUG' => 0, 'INFO' => 1, 'WARNING' => 2, 'ERROR' => 3, 'FATAL' => 4];
    private static array $logBuffer = [];
    private const BUFFER_SIZE = 100;
    
    public static function setLogLevel(string $level): void {
        $level = strtoupper($level);
        if (isset(self::$levels[$level])) {
            self::$logLevel = $level;
        }
    }
    
    public static function log(string $message, string $level = 'INFO'): void {
        $level = strtoupper($level);
        
        if (!isset(self::$levels[$level]) || self::$levels[$level] < self::$levels[self::$logLevel]) {
            return;
        }
        
        $timestamp = date('Y-m-d H:i:s');
        $logEntry = sprintf("[%s] [%s] %s\n", $timestamp, $level, trim($message));
        
        self::$logBuffer[] = $logEntry;
        
        if (count(self::$logBuffer) >= self::BUFFER_SIZE) {
            self::flushBuffer();
        }
    }
    
    public static function debug(string $message): void { self::log($message, 'DEBUG'); }
    public static function info(string $message): void { self::log($message, 'INFO'); }
    public static function warning(string $message): void { self::log($message, 'WARNING'); }
    public static function error(string $message): void { self::log($message, 'ERROR'); }
    public static function fatal(string $message): void { self::log($message, 'FATAL'); }
    
    private static function flushBuffer(): void {
        if (empty(self::$logBuffer)) {
            return;
        }
        
        $logContent = implode('', self::$logBuffer);
        
        if (self::$logFile) {
            if (file_put_contents(self::$logFile, $logContent, FILE_APPEND | LOCK_EX) === false) {
                fwrite(STDERR, "Failed to write to log file: " . self::$logFile . "\n");
            }
        } else {
            if ($level === 'ERROR' || $level === 'FATAL') {
                fwrite(STDERR, $logContent);
            } else {
                fwrite(STDOUT, $logContent);
            }
        }
        
        self::$logBuffer = [];
    }
    
    public static function setLogFile(string $file): void {
        $dir = dirname($file);
        if (!is_dir($dir) || !is_writable($dir)) {
            throw new RuntimeException("Log directory is not writable: $dir");
        }
        self::$logFile = $file;
        self::flushBuffer();
    }
    
    public static function shutdown(): void {
        self::flushBuffer();
    }
}

final class ErrorHandler {
    public static function handleFileRead(string $file): string {
        if (!Security::validatePath($file)) {
            throw new RuntimeException("Security violation: Invalid file path '$file'");
        }
        
        if (!is_file($file) || !is_readable($file)) {
            throw new RuntimeException("File $file does not exist or is not readable");
        }
        
        $fileSize = filesize($file);
        if ($fileSize === false) {
            throw new RuntimeException("Cannot determine size of file: $file");
        }
        
        if ($fileSize > MAX_FILE_SIZE) {
            throw new RuntimeException("File $file is too large ($fileSize bytes)");
        }
        
        $content = file_get_contents($file);
        if ($content === false) {
            $error = error_get_last();
            throw new RuntimeException("Failed to read $file: " . ($error['message'] ?? 'Unknown error'));
        }
        
        return $content;
    }
    
    public static function handle(Throwable $e, bool $verbose = false): void {
        $message = "Error: " . Security::sanitizeOutput($e->getMessage());
        fwrite(STDERR, $message . "\n");
        Logger::error($message);
        
        if ($verbose) {
            $details = sprintf("File: %s Line: %d", 
                Security::sanitizeOutput($e->getFile()), 
                $e->getLine()
            );
            fwrite(STDERR, $details . "\n");
            Logger::debug($details);
            
            if ($e->getPrevious()) {
                Logger::debug("Previous: " . $e->getPrevious()->getMessage());
            }
        }
    }
    
    public static function handleShutdown(): void {
        Logger::shutdown();
        
        $error = error_get_last();
        if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
            $message = sprintf("Fatal error: %s in %s on line %d",
                $error['message'],
                $error['file'],
                $error['line']
            );
            fwrite(STDERR, $message . "\n");
            Logger::fatal($message);
            
            ProcessCache::clearCache();
            ConnectionCache::clearCache();
            ConnectionHistory::clearHistory();
        }
    }
}

final class InputValidator {
    public static function validatePort($port): int {
        return Security::validateInteger($port, MIN_PORT, MAX_PORT);
    }
    
    public static function validateIpFilter(string $filter): string {
        if (!self::isValidIpOrCidr($filter)) {
            throw new InvalidArgumentException("Invalid IP or CIDR notation: $filter");
        }
        return $filter;
    }
    
    private static function isValidIpOrCidr(string $input): bool {
        $input = trim($input);
        if ($input === '') return false;
        
        if (str_contains($input, '/')) {
            $parts = explode('/', $input, 2);
            if (count($parts) !== 2) return false;
            
            list($ip, $mask) = $parts;
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
        return Security::validateInteger($interval, MIN_INTERVAL, MAX_INTERVAL);
    }
    
    public static function validateOutputFile(string $file): string {
        $dir = dirname($file);
        if ($dir !== '' && !is_dir($dir)) {
            if (!mkdir($dir, 0755, true)) {
                throw new InvalidArgumentException("Cannot create output directory: $dir");
            }
        }
        
        if ($dir !== '' && !is_writable($dir)) {
            throw new InvalidArgumentException("Output directory is not writable: $dir");
        }
        
        return $file;
    }
    
    public static function validatePid($pid): int {
        return Security::validateInteger($pid, 1, MAX_PID);
    }
}

final class ProcessCache {
    private static array $cache = [];
    private static int $lastBuild = 0;
    private static int $scanStartTime = 0;
    private static bool $building = false;
    private static ?array $connectionInodes = null;
    private static int $hits = 0;
    private static int $misses = 0;

    public static function getProcessMap(): array {
        $now = time();
        $ttl = Config::get('process_cache_ttl', 5);
        
        if (empty(self::$cache) || ($now - self::$lastBuild) > $ttl) {
            self::$misses++;
            self::$cache = self::buildProcessMap();
            self::$lastBuild = $now;
            self::enforceCacheLimits();
        } else {
            self::$hits++;
        }
        
        return self::$cache;
    }

    private static function buildProcessMap(): array {
        if (!Config::get('enable_process_scan', true)) {
            return [];
        }
        
        if (self::$building) {
            Logger::debug("Process map already being built, returning empty");
            return [];
        }
        
        self::$building = true;
        
        try {
            Security::validateProcFilesystem();
            
            $processMap = [];
            self::$connectionInodes = self::extractInodesFromProcNet();
            
            if (empty(self::$connectionInodes)) {
                Logger::info("No inodes found in /proc/net files");
                return $processMap;
            }

            self::$scanStartTime = time();
            $procDir = opendir('/proc');
            if ($procDir === false) {
                throw new RuntimeException("Cannot open /proc directory");
            }

            try {
                while (($entry = readdir($procDir)) !== false) {
                    if (!ctype_digit($entry)) continue;
                    
                    if ((time() - self::$scanStartTime) > MAX_PROCESS_SCAN_TIME) {
                        Logger::warning("Process scan timeout after " . MAX_PROCESS_SCAN_TIME . " seconds");
                        break;
                    }

                    $pid = (int)$entry;
                    $processDir = "/proc/{$pid}";

                    if (!is_dir($processDir)) continue;

                    $foundInodes = self::scanProcessInodes($pid);
                    if (!empty($foundInodes)) {
                        $processName = self::getProcessName($pid);
                        foreach ($foundInodes as $inode) {
                            $processMap[$inode] = $processName;
                        }
                        
                        if (count($processMap) >= count(self::$connectionInodes)) {
                            Logger::debug("Found all inodes, stopping scan early");
                            break;
                        }
                    }
                    
                    PerformanceTracker::recordOperation('process_scan');
                }
            } finally {
                closedir($procDir);
            }
            
            $duration = time() - self::$scanStartTime;
            Logger::info(sprintf("Built process map with %d entries in %ds", count($processMap), $duration));
            return $processMap;
        } finally {
            self::$building = false;
            self::$connectionInodes = null;
        }
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
            
            try {
                $handle = fopen($file, 'r');
                if ($handle === false) continue;
                
                $lineCount = 0;
                $maxConnections = Config::get('max_connections_per_scan', 50000);
                
                while (($line = fgets($handle)) !== false) {
                    $lineCount++;
                    if ($lineCount > $maxConnections) {
                        Logger::warning("Reached max connections limit for $file at line $lineCount");
                        break;
                    }
                    
                    if (preg_match('/\s+(\d+)$/', $line, $matches)) {
                        $inodes[$matches[1]] = true;
                    }
                    PerformanceTracker::recordOperation('inode_extraction');
                }
            } catch (Throwable $e) {
                Logger::error("Error reading $file: " . $e->getMessage());
            } finally {
                if (isset($handle) && is_resource($handle)) {
                    fclose($handle);
                }
                PerformanceTracker::stopTimer("read_$file");
            }
        }
        
        return $inodes;
    }
    
    private static function scanProcessInodes(int $pid): array {
        $foundInodes = [];
        $fdPath = "/proc/{$pid}/fd";
        
        if (!is_dir($fdPath)) return $foundInodes;

        $fds = scandir($fdPath);
        if ($fds === false) return $foundInodes;
        
        foreach ($fds as $fd) {
            if ($fd === '.' || $fd === '..') continue;
            
            $linkPath = $fdPath . '/' . $fd;
            $link = readlink($linkPath);
            if ($link && preg_match('/socket:\[(\d+)\]/', $link, $matches)) {
                $inode = $matches[1];
                if (isset(self::$connectionInodes[$inode])) {
                    $foundInodes[] = $inode;
                    if (count($foundInodes) >= count(self::$connectionInodes)) {
                        break;
                    }
                }
            }
            PerformanceTracker::recordOperation('fd_scan');
        }
        
        return $foundInodes;
    }
    
    private static function getProcessName(int $pid): string {
        $commPath = "/proc/{$pid}/comm";
        if (!is_readable($commPath)) {
            return "PID: $pid";
        }
        
        $processName = file_get_contents($commPath);
        if ($processName === false) {
            return "PID: $pid";
        }
        
        return trim($processName) . " (PID: $pid)";
    }
    
    private static function enforceCacheLimits(): void {
        $maxSize = Config::get('max_cache_size', MAX_CACHE_ENTRIES);
        if (count(self::$cache) > $maxSize) {
            self::$cache = array_slice(self::$cache, -$maxSize, null, true);
            Logger::info("Process cache trimmed to $maxSize entries");
        }
    }
    
    public static function clearCache(): void {
        self::$cache = [];
        self::$lastBuild = 0;
        self::$hits = 0;
        self::$misses = 0;
    }
    
    public static function disableProcessScan(): void {
        Config::set('enable_process_scan', false);
    }
    
    public static function getStats(): array {
        return [
            'cache_size' => count(self::$cache),
            'hits' => self::$hits,
            'misses' => self::$misses,
            'hit_rate' => (self::$hits + self::$misses) > 0 ? 
                round(self::$hits / (self::$hits + self::$misses) * 100, 2) : 0
        ];
    }
}

final class IPUtils {
    public static function hexToIpv4(string $hex): string {
        $hex = preg_replace('/[^0-9A-Fa-f]/', '', $hex);
        if (strlen($hex) !== IPV4_HEX_LENGTH) {
            return '0.0.0.0';
        }

        $parts = [];
        for ($i = 0; $i < IPV4_HEX_LENGTH; $i += 2) {
            $parts[] = hexdec(substr($hex, $i, 2));
        }

        return implode('.', array_reverse($parts));
    }

    public static function hexToIpv6(string $hex): string {
        $hex = preg_replace('/[^0-9A-Fa-f]/', '', $hex);
        if (strlen($hex) !== IPV6_HEX_LENGTH) {
            return '::';
        }

        $blocks = str_split($hex, 8);
        $blocks = array_reverse($blocks);
        $reordered = implode('', $blocks);
        
        $packed = pack('H*', $reordered);
        if ($packed === false) {
            return '::';
        }
        
        $addr = inet_ntop($packed);
        return $addr ?: '::';
    }

    public static function ipInCidr(string $ip, string $cidr): bool {
        $parts = explode('/', $cidr, 2);
        if (count($parts) !== 2) {
            return false;
        }
        
        list($subnet, $mask) = $parts;
        if (!is_numeric($mask)) {
            return false;
        }
        
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

        $maskLong = ($mask === 0) ? 0 : ((0xFFFFFFFF << (32 - $mask)) & 0xFFFFFFFF);
        return (($ipLong & $maskLong) === ($subnetLong & $maskLong));
    }

    private static function ipv6InCidr(string $ip, string $subnet, int $mask): bool {
        $ipBin = inet_pton($ip);
        $subnetBin = inet_pton($subnet);

        if ($ipBin === false || $subnetBin === false) return false;
        if ($mask === 0) return true;
        if ($mask >= 128) return $ip === $subnet;

        $binMask = str_repeat('f', intdiv($mask, 4));
        if ($mask % 4) {
            $binMask .= dechex(15 << (4 - ($mask % 4)));
        }
        $binMask = str_pad($binMask, 32, '0');
        $binMask = pack('H*', $binMask);
        if ($binMask === false) {
            return false;
        }
        
        return ($ipBin & $binMask) === ($subnetBin & $binMask);
    }
}

final class ConnectionCache {
    private static array $cache = [];
    private static int $hits = 0;
    private static int $misses = 0;
    
    public static function getConnections(string $file, int $family, bool $includeProcess = false): array {
        $maxConnections = Config::get('max_connections_per_scan', 50000);
        
        $key = $file . '_' . $family . '_' . (int)$includeProcess;
        
        $fileHash = self::getFileHash($file);
        if ($fileHash === null) {
            return [];
        }
        
        $cacheKey = $key . '_' . $fileHash;
        
        if (!isset(self::$cache[$cacheKey]) || self::isCacheExpired($cacheKey)) {
            self::$misses++;
            PerformanceTracker::startTimer("read_connections_$family");
            $connections = self::readConnections($file, $family, $includeProcess);
            
            if (count($connections) > $maxConnections) {
                $connections = array_slice($connections, 0, $maxConnections);
                Logger::warning("Limited connections to $maxConnections for $file");
            }
            
            self::$cache[$cacheKey] = [
                'data' => $connections,
                'timestamp' => time(),
                'size' => count($connections)
            ];
            PerformanceTracker::stopTimer("read_connections_$family");
            self::cleanupOldCache();
        } else {
            self::$hits++;
        }
        
        return self::$cache[$cacheKey]['data'];
    }
    
    private static function isCacheExpired(string $cacheKey): bool {
        return (time() - self::$cache[$cacheKey]['timestamp']) > Config::get('connection_cache_ttl', 1);
    }
    
    private static function getFileHash(string $file): ?string {
        if (!Security::validatePath($file)) {
            Logger::debug("Invalid path for file hash: $file");
            return null;
        }
        
        if (!is_file($file) || !is_readable($file)) {
            Logger::debug("Cannot access file for hash: $file");
            return null;
        }
        
        $fileSize = filesize($file);
        if ($fileSize === false || $fileSize > MAX_FILE_SIZE) {
            Logger::warning("File too large for hash: $file (" . ($fileSize ?: 'unknown') . " bytes)");
            return null;
        }
        
        $content = file_get_contents($file);
        if ($content === false) {
            Logger::debug("Failed to read file for hash: $file");
            return null;
        }
        
        return md5($content);
    }
    
    private static function readConnections(string $file, int $family, bool $includeProcess): array {
        if (!Security::validatePath($file)) {
            throw new RuntimeException("Security violation: Invalid file path '$file'");
        }

        if (!is_file($file) || !is_readable($file)) {
            return [];
        }

        $handle = fopen($file, 'r');
        if ($handle === false) {
            Logger::debug("Cannot open file: $file");
            return [];
        }

        $processMap = $includeProcess ? ProcessCache::getProcessMap() : null;

        fgets($handle);

        $connections = [];
        $lineCount = 0;
        $maxConnections = Config::get('max_connections_per_scan', 50000);
        
        try {
            while (($line = fgets($handle)) !== false) {
                $lineCount++;
                if ($lineCount > $maxConnections) {
                    Logger::warning("Reached max connections limit for $file at line $lineCount");
                    break;
                }
                
                PerformanceTracker::recordOperation('connection_parse');
                $line = trim($line);
                if ($line === '') continue;

                $fields = preg_split('/\s+/', $line);
                if (count($fields) < 10) continue;

                $connection = self::parseConnectionLine($fields, $family, $processMap);
                if ($connection !== null) {
                    $connections[] = $connection;
                }
            }
        } catch (Throwable $e) {
            Logger::error("Error reading connections from $file: " . $e->getMessage());
            throw $e;
        } finally {
            fclose($handle);
        }
        
        return $connections;
    }
    
    private static function parseConnectionLine(array $fields, int $family, ?array $processMap): ?array {
        if (!isset($fields[1], $fields[2], $fields[3], $fields[9])) {
            return null;
        }
        
        $localParts = explode(':', $fields[1], 2);
        $remoteParts = explode(':', $fields[2], 2);
        
        if (count($localParts) !== 2 || count($remoteParts) !== 2) {
            return null;
        }
        
        list($localIpHex, $localPortHex) = $localParts;
        list($remoteIpHex, $remotePortHex) = $remoteParts;
        
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
    
    private static function getProcessByInode(string $inode, array $processMap): string {
        static $processCache = [];
        static $cacheSize = 0;
        
        if (isset($processCache[$inode])) {
            return $processCache[$inode];
        }
        
        $process = $processMap[$inode] ?? '';
        $processCache[$inode] = $process;
        $cacheSize++;
        
        if ($cacheSize > 10000) {
            $processCache = [];
            $cacheSize = 0;
        }
        
        return $process;
    }
    
    private static function cleanupOldCache(): void {
        $now = time();
        $ttl = Config::get('connection_cache_ttl', 1);
        $maxSize = Config::get('max_cache_size', MAX_CACHE_ENTRIES);
        
        foreach (self::$cache as $key => $data) {
            if ($now - $data['timestamp'] > $ttl * 2) {
                unset(self::$cache[$key]);
            }
        }
        
        if (count(self::$cache) > $maxSize) {
            uasort(self::$cache, fn($a, $b) => $b['timestamp'] <=> $a['timestamp']);
            self::$cache = array_slice(self::$cache, 0, $maxSize, true);
        }
    }
    
    public static function clearCache(): void {
        self::$cache = [];
        self::$hits = 0;
        self::$misses = 0;
    }
    
    public static function getStats(): array {
        return [
            'cache_entries' => count(self::$cache),
            'hits' => self::$hits,
            'misses' => self::$misses,
            'hit_rate' => (self::$hits + self::$misses) > 0 ? 
                round(self::$hits / (self::$hits + self::$misses) * 100, 2) : 0
        ];
    }
}

final class OutputFormatter {
    public static function formatTable(array $connections, bool $showProcess = false): string {
        if (empty($connections)) {
            return "No connections found.\n";
        }

        self::sortConnections($connections);
        $output = "\nACTIVE TCP CONNECTIONS:\n";

        if ($showProcess) {
            $output .= sprintf("%-5s %-15s %-25s %-25s %-30s\n", 
                "Proto", "State", "Local Address", "Remote Address", "Process");
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
            $output .= sprintf("%-5s %-15s %-25s %-25s\n", 
                "Proto", "State", "Local Address", "Remote Address");
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

        return json_encode($output, JSON_PRETTY_PRINT | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR) . "\n";
    }

    public static function formatCsv(array $connections): string {
        if (empty($connections)) {
            return "";
        }
        
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

            uasort($stats['by_process'], fn($a, $b) => $b <=> $a);

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
                   $a['proto'] <=> $b['proto'] ?:
                   $a['state'] <=> $b['state'];
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
        $field = str_replace('"', '""', $field);
        if (str_contains($field, ',') || str_contains($field, '"') || 
            str_contains($field, "\n") || str_contains($field, "\r")) {
            return '"' . $field . '"';
        }
        return $field;
    }
    
    public static function stripColors(string $text): string {
        return preg_replace('/\033\[[0-9;]*m/', '', $text);
    }
}

final class ConnectionFilter {
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
        if (str_contains($filter, '/')) return IPUtils::ipInCidr($ip, $filter);
        return false;
    }
}

final class ConnectionHistory {
    private static array $history = [];

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
        
        $maxHistory = Config::get('max_history', 1000);
        if (count(self::$history) > $maxHistory) {
            array_shift(self::$history);
        }

        return $changes;
    }

    private static function getConnectionKey(array $conn): string {
        return sprintf("%s:%d-%s:%d-%s",
            $conn['local_ip'],
            $conn['local_port'],
            $conn['remote_ip'],
            $conn['remote_port'],
            $conn['state']
        );
    }
    
    public static function clearHistory(): void {
        self::$history = [];
    }
    
    public static function getHistoryStats(): array {
        $totalTracked = 0;
        foreach (self::$history as $entry) {
            $totalTracked += count($entry['connections']);
        }
        
        return [
            'history_size' => count(self::$history),
            'total_tracked' => $totalTracked
        ];
    }
}

final class SignalHandler {
    private static bool $shouldExit = false;
    private static int $startTime;
    private static bool $initialized = false;

    public static function init(): void {
        if (self::$initialized) {
            return;
        }
        
        if (!extension_loaded('pcntl')) {
            Logger::warning("PCNTL extension not loaded - signal handling disabled");
            return;
        }

        self::$startTime = time();
        self::$initialized = true;

        pcntl_signal(SIGINT, [self::class, 'handleSignal']);
        pcntl_signal(SIGTERM, [self::class, 'handleSignal']);
        pcntl_signal(SIGHUP, [self::class, 'handleSignal']);
        pcntl_signal(SIGUSR1, [self::class, 'handleSignal']);
        
        if (function_exists('pcntl_async_signals')) {
            pcntl_async_signals(true);
        }
    }

    public static function handleSignal(int $signo): void {
        switch ($signo) {
            case SIGINT:
            case SIGTERM:
                self::$shouldExit = true;
                $duration = time() - self::$startTime;
                echo "\n\nMonitoring stopped after {$duration} seconds.\n";
                Logger::info("Received signal $signo, shutting down after $duration seconds");
                Logger::shutdown();
                exit(0);
            case SIGHUP:
                Logger::info("Received SIGHUP, reloading configuration");
                Config::loadFromEnv();
                break;
            case SIGUSR1:
                $metrics = PerformanceTracker::getMetrics();
                Logger::debug("Debug signal received - Metrics: " . json_encode($metrics));
                break;
        }
    }

    public static function shouldExit(): bool {
        if (extension_loaded('pcntl')) {
            pcntl_signal_dispatch();
        }
        return self::$shouldExit;
    }
    
    public static function reset(): void {
        self::$shouldExit = false;
        self::$initialized = false;
    }
}

final class TCPConnectionMonitor {
    private array $options;
    
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

final class ConnectionWatcher {
    private TCPConnectionMonitor $monitor;
    
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
            self::displayChanges($changes, $iteration);

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

final class OptionParser {
    public static function parse(array $argv): array {
        $script = basename($argv[0] ?? 'tcp_monitor.php');
        
        $options = getopt("jlpv", [
            "json", "help", "listen", "established", "count", "processes",
            "timewait", "closewait", "finwait", "port:", "watch::",
            "local-ip:", "remote-ip:", "stats", "ipv4", "ipv6", "verbose",
            "csv", "output:", "log-file:", "no-processes", "debug",
            "config:", "env-file:", "version"
        ], $restIndex);

        if (isset($options['help'])) {
            self::displayHelp($script);
            exit(0);
        }
        
        if (isset($options['version'])) {
            echo "TCP Connection Monitor v1.0.0\n";
            exit(0);
        }
        
        self::loadConfig($options);
        self::validateOptions($options);
        return $options;
    }
    
    private static function loadConfig(array &$options): void {
        if (isset($options['env-file'])) {
            Config::loadFromEnvFile($options['env-file']);
        }
        
        if (isset($options['config'])) {
            Config::loadFromFile($options['config']);
        }
        
        Config::loadFromEnv();
        Logger::setLogLevel(Config::get('log_level', 'INFO'));
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
        
        if (isset($options['verbose']) || isset($options['v'])) {
            Logger::setLogLevel('INFO');
        }
        
        if (isset($options['no-processes'])) {
            ProcessCache::disableProcessScan();
        }
    }
    
    private static function displayHelp(string $script): void {
        echo <<<HELP
Usage: php {$script} [options]

Monitor TCP connections on Linux systems.

Options:
  --json              Output connections in JSON format
  --csv               Output connections in CSV format
  --listen            Show only listening sockets
  --established       Show only established connections
  --timewait          Show only TIME_WAIT connections
  --closewait         Show only CLOSE_WAIT connections
  --finwait           Show only FIN_WAIT1/FIN_WAIT2 connections
  --count             Only show counts (IPv4/IPv6/total)
  --processes         Show process information (slower)
  --no-processes      Disable process scanning (faster)
  --port <num>        Filter by port number
  --local-ip <ip>     Filter by local IP address (supports CIDR)
  --remote-ip <ip>    Filter by remote IP address (supports CIDR)
  --ipv4              Show only IPv4 connections
  --ipv6              Show only IPv6 connections
  --watch [sec]       Refresh continuously (default: 2s)
  --stats             Show detailed statistics
  --output <file>     Write output to file
  --log-file <file>   Write logs to file
  --config <file>     Load configuration from JSON file
  --env-file <file>   Load environment variables from file
  --verbose, -v       Show performance metrics
  --debug             Enable debug logging
  --version           Show version information
  --help              Show this help message

Examples:
  php {$script} --listen --processes
  php {$script} --port 80 --established
  php {$script} --watch=5 --local-ip 192.168.1.0/24
  php {$script} --json --output connections.json

HELP;
    }
}

final class Exporter {
    public static function toFile(string $content, string $filename): void {
        $tempFile = Security::createTempFile('tcpmon_', dirname($filename));
        
        if (file_put_contents($tempFile, $content, LOCK_EX) === false) {
            unlink($tempFile);
            throw new RuntimeException("Failed to write to temporary file: $tempFile");
        }
        
        if (!rename($tempFile, $filename)) {
            unlink($tempFile);
            throw new RuntimeException("Failed to rename temporary file to: $filename");
        }
        
        Logger::info("Output written to: $filename");
    }
    
    public static function toFileWithBackup(string $content, string $filename): void {
        if (file_exists($filename)) {
            $backup = $filename . '.bak';
            if (file_exists($backup)) {
                unlink($backup);
            }
            rename($filename, $backup);
            Logger::debug("Created backup: $backup");
        }
        
        self::toFile($content, $filename);
    }
}

final class Application {
    public static function run(): void {
        try {
            PerformanceTracker::start();

            if (php_sapi_name() !== 'cli') {
                throw new RuntimeException("This script must be run from the command line.");
            }

            if (PHP_OS_FAMILY !== 'Linux') {
                throw new RuntimeException("This script is only supported on Linux systems.");
            }

            Security::validateProcFilesystem();

            if (function_exists('posix_geteuid') && posix_geteuid() !== 0) {
                fwrite(STDERR, "Note: Some information may be limited without root privileges.\n");
                Logger::info("Running without root privileges - some information may be limited");
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
                if (isset($options['output'])) {
                    $output = OutputFormatter::stripColors($output);
                }
            } else {
                $output = OutputFormatter::formatTable($connections, $options['processes'] ?? false);
                if (isset($options['output'])) {
                    $output = OutputFormatter::stripColors($output);
                }
            }

            if (isset($options['output'])) {
                Exporter::toFileWithBackup($output, $options['output']);
                echo "Output written to: {$options['output']}\n";
            } else {
                echo $output;
            }

            self::displayPerformanceMetrics($options);

        } catch (Throwable $e) {
            ErrorHandler::handle($e, $options['verbose'] ?? false);
            exit(1);
        }
    }

    private static function displayPerformanceMetrics(array $options): void {
        if (isset($options['verbose']) || isset($options['v']) || isset($options['debug'])) {
            $metrics = PerformanceTracker::getMetrics();
            $processStats = ProcessCache::getStats();
            $connectionStats = ConnectionCache::getStats();
            $historyStats = ConnectionHistory::getHistoryStats();
            
            echo "\nPerformance Metrics:\n";
            echo str_repeat("-", 40) . "\n";
            echo "Execution time: {$metrics['execution_time']}s\n";
            echo "Memory peak: {$metrics['memory_peak_mb']} MB\n";
            echo "Operations: {$metrics['operations']}\n";
            
            echo "\nCache Statistics:\n";
            echo "  Process cache: {$processStats['cache_size']} entries, ";
            echo "{$processStats['hit_rate']}% hit rate\n";
            echo "  Connection cache: {$connectionStats['cache_entries']} entries, ";
            echo "{$connectionStats['hit_rate']}% hit rate\n";
            
            echo "\nHistory Stats:\n";
            echo "  History size: {$historyStats['history_size']}\n";
            echo "  Total tracked: {$historyStats['total_tracked']}\n";
            
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

register_shutdown_function([ErrorHandler::class, 'handleShutdown']);

Application::run();
