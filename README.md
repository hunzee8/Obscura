# Obscura 🌑 - Complete Network Anonymization Suite


## 🔥 Features

### 🕵️ Obscura (Root Required)
- Transparent Tor routing via iptables
- Automatic browser hardening against WebRTC leaks
- DNS/IPv6 leak prevention
- MAC address randomization
- Automatic IP rotation

### 🔍 SecurityCheck (No Root)
- Instant Tor connectivity verification
- Comprehensive leak testing
- Color-coded results
- JSON output option (`--json`)

## 💻 Installation

### Kali/Debian/Ubuntu
```bash
sudo apt update && sudo apt install -y tor python3-pip git
git clone https://github.com/yourusername/Obscura.git
cd Obscura
sudo pip3 install -r requirements.txt
sudo python3 setup.py install
```

### Arch Linux
```bash
sudo pacman -S --needed tor python-pip git
git clone https://github.com/yourusername/Obscura.git
cd Obscura
sudo pip install -r requirements.txt
sudo python setup.py install
```

## 🛠 Obscura Commands

### Core Functionality
| Command | Description |
|---------|-------------|
| `sudo obscura --load` | Enable Tor routing + DNS protection |
| `sudo obscura --flush` | Reset all network rules |
| `sudo obscura --refresh` | Get new Tor circuit |
| `sudo obscura --auto --interval 1800` | Auto-rotate IP every 30 mins |

### Browser Protection
| Command | Description |
|---------|-------------|
| `sudo obscura --webrtc` | Harden all detected browsers |
| `sudo obscura --webrtc --kill` | Apply changes immediately (kills browsers) |
| `sudo obscura --mac-random` | Randomize MAC address |

### Information
| Command | Description |
|---------|-------------|
| `obscura --info` | Show current IP and Tor status |
| `obscura --status` | Check protection status |

## 🔎 SecurityCheck Commands

### Basic Checks
| Command | Description |
|---------|-------------|
| `securitycheck --tor` | Verify Tor connection |
| `securitycheck --dns` | Test for DNS leaks |
| `securitycheck --webrtc` | Check WebRTC leaks |
| `securitycheck --ipv6` | Detect IPv6 leaks |

### Advanced Options
| Command | Description |
|---------|-------------|
| `securitycheck --all` | Run all security tests |
| `securitycheck --json` | Output results in JSON format |
| `securitycheck --continuous 300` | Run checks every 5 minutes |

## 🚀 Usage Examples

### Full Anonymity Setup
```bash
# Enable network protection
sudo obscura --load --webrtc --mac-random

# Verify setup
securitycheck --all
```

### Temporary Browsing Session
```bash
# Start protected session
sudo obscura --load --webrtc --kill

# When done
sudo obscura --flush
```

### Security Auditor Mode
```bash
# Continuous monitoring
securitycheck --continuous 600 --json > audit.log
```


## 🚨 Troubleshooting

### Common Issues
1. **Tor not running**:
   ```bash
   sudo systemctl start tor
   ```

2. **Browser changes not applying**:
   ```bash
   sudo obscura --webrtc --kill
   ```

3. **DNS leaks detected**:
   ```bash
   sudo obscura --flush && sudo obscura --load
   ```

4. **Permission errors**:
   ```bash
   sudo chown -R $USER:$USER /var/log/obscura.log
   ```
