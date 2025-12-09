const fs = require('fs');
const csv = require('csv-parser');
const path = require('path');
const moment = require('moment-timezone');
const yargs = require('yargs');
require('dotenv').config();

// Import utility modules
// NetworkUtils: Likely contains IP/MAC validation, IP math (e.g., getNetworkAddress)
const NetworkUtils = require('./utils/networkUtils');
// PythonNetmikoExecutor: Handles spawning the Python script for SSH communication
const PythonNetmikoExecutor = require('./pythonNetmikoExecutor');

class DHCPAutomation {
    constructor(csvFilePath) {
        this.csvFilePath = csvFilePath;
        this.zoneData = {};              // Stores configuration from zone_master.json
        this.storeData = new Map();      // Grouped data: Map<gateway_storeCode, {gateway, storeCode, aps: [...]}>
        this.logs = [];
        this.commands = [];              // Generated Cisco configuration commands
        this.sshResults = [];
        this.executionSummary = {
            totalGateways: 0,
            totalStores: 0,
            totalAPs: 0,
            commandsGenerated: 0,
            sshSuccess: false,
            sshError: null,
            executionMode: process.env.EXECUTION_MODE || 'both'
        };
        this.istTime = moment().tz('Asia/Kolkata');
        
        // Initialize Python Netmiko Executor
        this.pythonExecutor = new PythonNetmikoExecutor();
    }

    async initialize() {
        this.log('INFO', 'DHCP Automation Script Started');
        this.log('INFO', `Processing CSV file: ${this.csvFilePath}`);
        this.log('INFO', `Execution Mode: ${this.executionSummary.executionMode}`);
        
        await this.loadZoneData(); // Load network zone configurations
        this.detectDelimiterAndProcess(); // Start CSV processing
    }

    // Load DNS/other config details from zone_master.json
    async loadZoneData() {
        try {
            const zonePath = path.join(__dirname, 'config', 'zone_master.json');
            this.zoneData = JSON.parse(fs.readFileSync(zonePath, 'utf8'));
            this.log('INFO', 'Zone master data loaded successfully');
            this.log('DEBUG', `Available zones: ${Object.keys(this.zoneData).join(', ')}`);
        } catch (error) {
            this.log('ERROR', `Failed to load zone data: ${error.message}`);
            process.exit(1);
        }
    }

    // Centralized logging function (to console and a file)
    log(level, message) {
        const timestamp = moment().tz('Asia/Kolkata').format('YYYY-MM-DD HH:mm:ss');
        const logEntry = `[${timestamp}] [${level}] ${message}`;
        
        console.log(logEntry);
        this.logs.push(logEntry);
        
        // Write to a time-stamped log file
        try {
            const logDir = path.join(__dirname, 'logs');
            if (!fs.existsSync(logDir)) {
                fs.mkdirSync(logDir, { recursive: true });
            }
            
            const logFile = path.join(logDir, `dhcp_automation_${this.istTime.format('YYYYMMDD_HHmmss')}.log`);
            fs.appendFileSync(logFile, logEntry + '\n');
        } catch (error) {
            console.error('Failed to write to log file:', error.message);
        }
    }

    // Determines if the input file is CSV (comma) or TSV (tab)
    detectDelimiterAndProcess() {
        if (!fs.existsSync(this.csvFilePath)) {
            this.log('ERROR', `CSV file not found: ${this.csvFilePath}`);
            this.showUsage();
            return;
        }

        const fileContent = fs.readFileSync(this.csvFilePath, 'utf8');
        const lines = fileContent.split('\n');
        const firstLine = lines[0];
        
        const tabCount = (firstLine.match(/\t/g) || []).length;
        const commaCount = (firstLine.match(/,/g) || []).length;
        
        let delimiter = ',';
        if (tabCount > commaCount) {
            delimiter = '\t';
            this.log('INFO', 'Detected tab-separated file (TSV)');
        } else {
            this.log('INFO', 'Detected comma-separated file (CSV)');
        }

        this.processCSV(delimiter);
    }

    // Cleans up column keys and values
    sanitizeRecord(record) {
        const sanitized = {};
        for (const [key, value] of Object.entries(record)) {
            // Clean the key names (remove extra spaces, non-printable chars)
            const cleanKey = key.trim().replace(/[^\x20-\x7E]/g, '');
            // NetworkUtils.sanitizeInput removes leading/trailing spaces, etc.
            sanitized[cleanKey] = NetworkUtils.sanitizeInput(value);
        }
        return sanitized;
    }

    // Validates essential fields (IPs, MACs, required data)
    validateRecord(record) {
        const errors = [];
        
        // Flexible field checking for common CSV header names
        const storeCode = record.StoreCode || record.storecode || record.Store_code;
        if (!storeCode || storeCode.length === 0) {
            errors.push('StoreCode is required');
        }

        const wapIP = record['WAP IP'] || record['WAP_IP'] || record.wapip || record.WAPIP || record['Wap IP'] || record['wap ip'];
        if (!NetworkUtils.isValidIP(wapIP)) {
            errors.push(`Invalid WAP IP: ${wapIP}`);
        }

        const subnetMask = record['Subnet Mask'] || record['Subnet_Mask'] || record.subnetmask || record.SubnetMask || record['Subnet mask'] || record['subnet mask'];
        if (!NetworkUtils.isValidIP(subnetMask)) {
            errors.push(`Invalid Subnet Mask: ${subnetMask}`);
        }

        const apMac = record.AP_MAC || record['AP_MAC'] || record.apmac || record.APMAC || record['AP MAC'] || record['ap mac'] || record['AP-MAC'];
        if (!NetworkUtils.isValidMAC(apMac)) {
            errors.push(`Invalid AP MAC: ${apMac}`);
        }

        const gateway = record.Gateway || record.gateway || record['Default Gateway'] || record['default gateway'];
        if (!NetworkUtils.isValidIP(gateway)) {
            errors.push(`Invalid Gateway IP: ${gateway}`);
        }

        const zone = record.Zone || record.zone;
        if (!this.zoneData[zone]) {
            errors.push(`Zone not found in master data: ${zone}`);
        }

        return errors;
    }

    // Streams and processes the CSV/TSV file
    processCSV(delimiter = ',') {
        this.log('INFO', `Processing CSV file with ${delimiter === '\t' ? 'tab' : 'comma'} delimiter...`);

        const results = [];
        
        fs.createReadStream(this.csvFilePath)
            .pipe(csv({
                separator: delimiter,
                // Clean up headers during parsing
                mapHeaders: ({ header, index }) => header.trim().replace(/[^\x20-\x7E]/g, '')
            }))
            .on('data', (data) => {
                const sanitized = this.sanitizeRecord(data);
                results.push(sanitized);
            })
            .on('end', async () => {
                this.log('INFO', `CSV processing completed. ${results.length} records found.`);
                this.groupByGatewayAndStore(results); // Organize data for command generation
                this.generateCommands();          // Create the Cisco configuration
                await this.executeAndGenerateReport(); // Run SSH (if mode allows) and report
            })
            .on('error', (error) => {
                this.log('ERROR', `CSV processing error: ${error.message}`);
            });
    }

    // Groups APs under their respective Gateway/Store combinations
    groupByGatewayAndStore(records) {
        let validRecords = 0;
        let invalidRecords = 0;

        records.forEach((record, index) => {
            const errors = this.validateRecord(record);
            
            if (errors.length > 0) {
                this.log('WARN', `Record ${index + 1} validation failed: ${errors.join(', ')}`);
                invalidRecords++;
                return;
            }

            validRecords++;
            
            // Get validated fields (flexible name support)
            const storeCode = record.StoreCode || record.storecode || record.Store_code;
            const wapIP = record['WAP IP'] || record['WAP_IP'] || record.wapip || record.WAPIP;
            const subnetMask = record['Subnet Mask'] || record['Subnet_Mask'] || record.subnetmask || record.SubnetMask;
            const apMac = record.AP_MAC || record['AP_MAC'] || record.apmac || record.APMAC;
            const zone = record.Zone || record.zone;
            const gateway = record.Gateway || record.gateway;

            // Create unique key by combining gateway and store code
            const gatewayKey = `${gateway}_${storeCode}`;
            
            if (!this.storeData.has(gatewayKey)) {
                // Initialize entry for a new Gateway/Store combination
                this.storeData.set(gatewayKey, {
                    gateway: gateway,
                    storeCode: storeCode,
                    business: record.Business || record.business,
                    zone: zone,
                    subnetMask: subnetMask,
                    aps: []
                });
            }

            // Add the AP to the store's list
            const store = this.storeData.get(gatewayKey);
            store.aps.push({
                mac: apMac,
                ip: wapIP,
                serviceProvider: record.ServiceProvider || record.serviceprovider || record['Service Provider'],
                customer: record.Customer || record.customer,
                location: record.Location || record.location
            });
        });

        this.log('INFO', `Records processed: ${validRecords} valid, ${invalidRecords} invalid`);
        this.log('INFO', `Unique gateway/store combinations found: ${this.storeData.size}`);
        
        // Update execution summary statistics
        this.executionSummary.totalGateways = this.storeData.size;
        this.executionSummary.totalStores = new Set(Array.from(this.storeData.values()).map(s => s.storeCode)).size;
        this.executionSummary.totalAPs = Array.from(this.storeData.values()).reduce((sum, store) => sum + store.aps.length, 0);
    }

    // Generates Cisco IOS DHCP configuration commands
    generateCommands() {
        if (this.storeData.size === 0) {
            this.log('ERROR', 'No valid store data found to generate commands. Aborting command generation.');
            return;
        }

        this.log('INFO', 'Generating DHCP commands...');

        for (const [gatewayKey, store] of this.storeData) {
            
            try {
                // Determine network/broadcast addresses
                const networkIP = NetworkUtils.getNetworkAddress(store.aps[0].ip, store.subnetMask);
                const zoneInfo = this.zoneData[store.zone];
                
                if (!zoneInfo) {
                    this.log('ERROR', `Zone info not found for store ${store.storeCode}, zone: ${store.zone}`);
                    continue;
                }

                // --- 1. Global DHCP Pool for Store WAPs (Dynamic IPs) ---
                this.commands.push(`! Commands for Gateway: ${store.gateway}, Store: ${store.storeCode}`);
                this.commands.push('configure terminal');
                this.commands.push('service dhcp');
                
                this.commands.push(`ip dhcp pool JIO_WAP_${store.storeCode}`);
                this.commands.push(`network ${networkIP} ${store.subnetMask}`);
                this.commands.push(`default-router ${store.gateway}`); // Router's IP for the LAN
                // Use DNS from zone_master.json
                this.commands.push(`dns-server ${zoneInfo.Primary_DNS_IP} ${zoneInfo.Secondary_DNS_IP}`); 
                this.commands.push('lease infinite');
                this.commands.push('exit');

                // Sort AP IPs to determine exclusion ranges
                const sortedAPIPs = NetworkUtils.sortIPs(store.aps.map(ap => ap.ip));
                const firstAPIP = sortedAPIPs[0];
                const lastAPIP = sortedAPIPs[sortedAPIPs.length - 1];
                
                const networkEndIP = this.getBroadcastAddress(networkIP, store.subnetMask);
                
                // Convert IPs to integers for arithmetic comparison
                const networkStartInt = NetworkUtils.ipToInt(networkIP);
                const networkEndInt = NetworkUtils.ipToInt(networkEndIP);
                const firstAPInt = NetworkUtils.ipToInt(firstAPIP);
                const lastAPInt = NetworkUtils.ipToInt(lastAPIP);
                
                const excludeRanges = [];
                
                // Exclude range before the first AP IP (to preserve Gateway/other static IPs)
                if (firstAPInt > networkStartInt + 1) { // +1 to start after network address
                    const rangeStart = NetworkUtils.intToIP(networkStartInt + 1); 
                    const rangeEnd = NetworkUtils.intToIP(firstAPInt - 1);
                    if (NetworkUtils.ipToInt(rangeStart) <= NetworkUtils.ipToInt(rangeEnd)) {
                        excludeRanges.push(`${rangeStart} ${rangeEnd}`);
                    }
                }
                
                // Exclude range after the last AP IP (to preserve future static IPs/Broadcast)
                if (lastAPInt < networkEndInt - 1) { // -1 to end before broadcast address
                    const rangeStart = NetworkUtils.intToIP(lastAPInt + 1);
                    const rangeEnd = NetworkUtils.intToIP(networkEndInt - 1);
                    if (NetworkUtils.ipToInt(rangeStart) <= NetworkUtils.ipToInt(rangeEnd)) {
                        excludeRanges.push(`${rangeStart} ${rangeEnd}`);
                    }
                }
                
                // Add exclude commands for the main WAP pool
                if (excludeRanges.length > 0) {
                    excludeRanges.forEach(range => {
                        this.commands.push(`ip dhcp excluded-address ${range}`);
                    });
                }
                
                // --- 2. Individual AP DHCP Host Entries (Static Binding) ---
                store.aps.forEach((ap, index) => {
                    const poolNumber = (index + 1).toString().padStart(2, '0');
                    // Create a DHCP pool with 'host' command for static binding
                    this.commands.push(`ip dhcp pool JIO_WAP${poolNumber}_${store.storeCode}`);
                    this.commands.push(`host ${ap.ip} ${store.subnetMask}`);
                    this.commands.push(`hardware-address ${ap.mac} ethernet`);
                    this.commands.push('exit');
                });

                // --- 3. Fixed/Standard Configuration Blocks (VPN/Guest ACLs/VRF) ---
                // These commands are standard and don't change per store (likely for Guest WiFi/VRF/Security)
                this.commands.push('vrf definition INET');                
                this.commands.push(' address-family ipv4');
                this.commands.push(' exit-address-family');                
                this.commands.push(' address-family ipv6');
                this.commands.push(' exit-address-family');                
                this.commands.push('ip access-list extended BLOCK_VPN');
                this.commands.push(' permit udp [REDACTED_VPN_SOURCE_NET] [REDACTED_VPN_WILDCARD] host 8.8.8.8 eq domain');
                this.commands.push(' permit udp host 8.8.8.8 [REDACTED_VPN_SOURCE_NET] [REDACTED_VPN_WILDCARD] eq domain');
                this.commands.push(' deny   tcp any any eq 1723'); // PPTP
                this.commands.push(' deny   udp any any eq domain'); // Block general DNS
                this.commands.push(' deny   gre any any');
                this.commands.push(' deny   udp any any eq 1701'); // L2TP
                this.commands.push(' deny   esp any any'); // IPsec
                this.commands.push(' deny   tcp any any eq 1194'); // OpenVPN TCP
                this.commands.push(' deny   udp any any eq 1194'); // OpenVPN UDP
                this.commands.push(' deny   tcp any any eq 8080');
                this.commands.push(' deny   tcp any any eq 4433');
                this.commands.push(' permit ip any any');                
                this.commands.push('ip access-list extended RR_GUEST');
                this.commands.push(' deny   ip [REDACTED_GUEST_NET] [REDACTED_GUEST_WILDCARD] [REDACTED_INTERNAL_NET] 0.255.255.255'); // Block internal access
                this.commands.push(' permit ip [REDACTED_GUEST_NET] [REDACTED_GUEST_WILDCARD] any'); // Allow general internet access
                this.commands.push('ip dhcp excluded-address vrf INET [REDACTED_GUEST_GW_IP]');
                this.commands.push('ip dhcp pool RR_GUEST');
                this.commands.push(' vrf INET');
                this.commands.push(' network [REDACTED_GUEST_NET] [REDACTED_GUEST_MASK]');
                this.commands.push(' default-router [REDACTED_GUEST_GW_IP]');
                this.commands.push(' dns-server 8.8.8.8');                          
                this.commands.push('ip scp enable'); // Enable Secure Copy Protocol
                this.commands.push('end');
                this.commands.push('write memory'); // Save configuration
                this.commands.push(''); 
                
            } catch (error) {
                this.log('ERROR', `Failed to generate commands for gateway ${store.gateway}, store ${store.storeCode}: ${error.message}`);
            }
        }

        this.executionSummary.commandsGenerated = this.commands.length;
    }

    // Helper method to calculate the broadcast address from network IP and mask
    getBroadcastAddress(networkIP, subnetMask) {
        const networkInt = NetworkUtils.ipToInt(networkIP);
        const maskInt = NetworkUtils.ipToInt(subnetMask);
        // Bitwise OR of network address and inverted mask (performing unsigned shift >>> 0)
        const broadcastInt = networkInt | (~maskInt >>> 0); 
        return NetworkUtils.intToIP(broadcastInt);
    }

    // Extracts the commands specific to a single store (for targeted execution)
    getStoreCommands(storeCode) {
        const commands = [];
        let inStoreSection = false;
        
        for (const command of this.commands) {
            // Find the start marker
            if (command.includes(`Store: ${storeCode}`)) {
                inStoreSection = true;
                continue;
            }
            
            if (inStoreSection) {
                // Empty line after commands marks the end of the section
                if (command.trim() === '' && commands.length > 0) {
                    break;
                }
                // Add command, excluding the initial comment line
                if (command.trim() && !command.startsWith('!')) {
                    commands.push(command);
                }
            }
        }
        
        return commands;
    }

    // Executes commands via Python Netmiko and generates the final report
    async executeAndGenerateReport() {
        this.log('INFO', 'Starting command execution and report generation...');

        // Report structure initialization
        const report = [
            '='.repeat(80),
            'RRL STORES DHCP AUTOMATION REPORT',
            '='.repeat(80),
            // ... (summary stats)
            ''
        ];

        // Python Netmiko Execution Section
        if (this.commands.length > 0 && 
            (this.executionSummary.executionMode === 'ssh-only' || 
             this.executionSummary.executionMode === 'both')) {
            
            report.push('PYTHON NETMIKO EXECUTION:');
            report.push('-'.repeat(40));
            
            try {
                // Process each unique gateway/store combination separately
                const gatewayResults = [];
                let overallSuccess = true;
                let successfulGateways = 0;
                let failedGateways = 0;

                for (const [gatewayKey, store] of this.storeData) {
                    const deviceIP = store.gateway; 
                    
                    try {
                        // Prepare data for the Python executor
                        const storeData = [{
                            storeCode: store.storeCode,
                            commands: this.getStoreCommands(store.storeCode)
                        }];
                        
                        // Execute the commands on the router via Python
                        const pythonResult = await this.pythonExecutor.executeStoreCommands(
                            deviceIP, 
                            storeData, 
                            this.log.bind(this)
                        );
                        
                        // Aggregate results
                        gatewayResults.push({
                            gateway: deviceIP,
                            store: store.storeCode,
                            result: pythonResult
                        });
                        
                        if (pythonResult.success) {
                            successfulGateways++;
                        } else {
                            failedGateways++;
                            overallSuccess = false;
                        }
                        
                    } catch (error) {
                        failedGateways++;
                        overallSuccess = false;
                        this.log('ERROR', `💥 Unexpected error processing gateway ${deviceIP}: ${error.message}`);
                    }
                }

                // Append detailed execution results to the report
                gatewayResults.forEach(gwResult => {
                    // ... (report formatting logic)
                });
                
                this.executionSummary.sshSuccess = overallSuccess;
                this.executionSummary.sshError = overallSuccess ? null : `${failedGateways} gateways failed`;
                
            } catch (error) {
                // Catch errors related to the Python process itself
                this.executionSummary.sshSuccess = false;
                this.executionSummary.sshError = error.message;
            }
        } else {
            report.push('SSH Execution: SKIPPED (based on execution mode)');
        }

        // Save report to file and display console summary
        // ... (File saving and summary display logic)
    }

    // ... (displayConsoleSummary, showUsage, and yargs config remain largely the same)
}

// ... (yargs configuration and script initialization)