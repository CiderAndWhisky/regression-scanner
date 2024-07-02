<?php
declare(strict_types=1);

date_default_timezone_set('UTC');

class OpenSSHScanner
{
    public string $log_file;
    private string $light_gray_color = "\033[90m";
    private string $dimmed_gray_color = "\033[90m";
    private string $dimmed_green_color = "\033[2;32m";
    private string $red_color = "\033[31m";
    private string $light_orange_color = "\033[38;5;214m";
    private string $reset_color = "\033[0m";
    private string $log_dir = 'logs';
    private array $vulnerable_ips = [];

    public function __construct()
    {
        $this->log_file = $this->log_dir . '/scan.log';
    }

    public function main(array $argv): void
    {
        $this->banner();
        if (count($argv) < 3) {
            echo "Usage: php script.php -u IP[Range] -p Port\n";
            exit(1);
        }

        $options = getopt("u:p:");
        $this->createLogDir();

        if (isset($options['u']) && isset($options['p'])) {
            $target = $options['u'];
            $port = (int)$options['p'];
            if (str_contains($target, '/')) {
                $this->handleCidr($target, $port);
            } else {
                $this->testHost($target, $port);
            }
        }

        if (count($this->vulnerable_ips) > 0) {
            $this->printMessage('info', "Scanning complete. Vulnerable hosts:");
            foreach ($this->vulnerable_ips as $ip) {
                $this->printMessage('vulnerable', $ip);
            }
        }
        $this->printMessage('info', "Scanning complete.");
    }

    public function banner(): void
    {
        echo <<<EOT
{$this->light_orange_color}
▒█▀▀▀█ █▀▀█ █▀▀ █▀▀▄ ▒█▀▀▀█ ▒█▀▀▀█ ▒█░▒█ 　 ▒█▀▀▀█ █▀▀ █▀▀█ █▀▀▄ █▀▀▄ █▀▀ █▀▀█ 
▒█░░▒█ █░░█ █▀▀ █░░█ ░▀▀▀▄▄ ░▀▀▀▄▄ ▒█▀▀█ 　 ░▀▀▀▄▄ █░░ █▄▄█ █░░█ █░░█ █▀▀ █▄▄▀ 
▒█▄▄▄█ █▀▀▀ ▀▀▀ ▀░░▀ ▒█▄▄▄█ ▒█▄▄▄█ ▒█░▒█ 　 ▒█▄▄▄█ ▀▀▀ ▀░░▀ ▀░░▀ ▀░░▀ ▀▀▀ ▀░▀▀
  {$this->reset_color}{$this->dimmed_gray_color}-> Bulk Scanning Tool for OpenSSH RCE CVE-2024-6387, CVE-2006-5051 and CVE-2008-4109.
{$this->reset_color}
EOT;
    }

    public function createLogDir(): void
    {
        if (!is_dir($this->log_dir)) {
            mkdir($this->log_dir, 0777, true);
            $this->printMessage('info', "Log directory created: {$this->log_dir}");
        }
    }

    public function printMessage(string $level, string $message): void
    {
        $color = $this->reset_color;
        switch ($level) {
            case 'vulnerable':
                $color = $this->light_orange_color;
                break;
            case 'info':
                $color = $this->dimmed_gray_color;
                break;
            case 'ok':
                $color = $this->dimmed_green_color;
                break;
            case 'error':
                $color = $this->red_color;
                break;
        }
        $time = date('Y-m-d H:i:s');
        echo "[{$this->light_gray_color}{$time}{$this->reset_color}] $color $message{$this->reset_color}\n";
        $this->logMessage($message);
    }

    public function logMessage(string $message): void
    {
        file_put_contents($this->log_file, "$message\n", FILE_APPEND);
    }

    public function handleCidr(string $cidr, int $port): void
    {
        $ips = $this->cidrToRange($cidr);
        foreach ($ips as $ip) {
            $this->testHost($ip, $port);
        }
    }

    public function cidrToRange(string $cidr): array
    {
        list($ip, $mask) = explode('/', $cidr);
        $mask = 32 - $mask;
        $ip = ip2long($ip);
        $start = $ip & ((-1 << $mask));
        $end = $ip | ((1 << $mask) - 1);
        $ips = [];
        for ($i = $start; $i <= $end; $i++) {
            $ips[] = long2ip($i);
        }
        return $ips;
    }

    public function testHost(string $ip, int $port): void
    {
        $version = $this->getSshVersion($ip, $port);
        if ($version) {
            $message = "OpenSSH version $version $ip:$port";
            list($is_vulnerable, $cve_number) = $this->isVulnerable("$version");
            if ($is_vulnerable) {
                $vulnerability_message = "$cve_number OpenSSH version $version $ip:$port";
                $this->printMessage('vulnerable', $vulnerability_message);
                $this->vulnerable_ips[] = $ip . ':' . $port;
            } elseif ($version == "Invalid SSH identification string.") {
                $this->printMessage('info', "$version $ip:$port");
            } else {
                $this->printMessage('ok', $message);
            }
        } else {
            $this->printMessage('info', "No OpenSSH $ip:$port");
        }
    }

    public function getSshVersion(string $ip, int $port): ?string
    {
        $socket = @fsockopen($ip, $port, $errno, $error_message, 1);
        if (!$socket) {
            return null;
        }
        fwrite($socket, "\x00");
        $response = fgets($socket, 1024);
        fclose($socket);
        if (is_string($response)) {
            if (str_starts_with($response, "SSH-2.0-OpenSSH")) {
                return explode('-', $response)[2];
            }
        }
        return "Invalid SSH identification string.";
    }

    public function isVulnerable($version): array
    {
        if (str_starts_with($version, "OpenSSH_")) {
            $version_num = explode('_', $version)[1];
            try {
                $parsed_version = $this->parseVersion($version_num);
            } catch (Exception) {
                return [false, null];
            }

            if ($parsed_version < $this->parseVersion("4.4")) {
                return [true, "CVE-2006-5051, CVE-2008-4109"];
            }
            if ($this->parseVersion("8.5") <= $parsed_version && $parsed_version < $this->parseVersion("9.8")) {
                return [true, "CVE-2024-6387"];
            }
        }
        return [false, null];
    }

    public function parseVersion(string $version): float|int
    {
        if (preg_match('/(\d+)\.(\d+)(p\d+)?/', $version, $matches)) {
            $major = (int)$matches[1];
            $minor = (int)$matches[2];
            return $major * 1000 + $minor;
        }
        throw new Exception("Invalid version format");
    }
}

$scanner = new OpenSSHScanner();
try {
    $scanner->main($argv);
    $scanner->printMessage('info', "Scanning complete. Log file created: {$scanner->log_file}");
} catch (Exception $e) {
    $scanner->printMessage('error', "Scanning interrupted: " . $e->getMessage());
    exit(1);
}
