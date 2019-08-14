module.exports = {
    /**
     * Name of the integration which is displayed in the Polarity integrations user interface
     *
     * @type String
     * @required
     */
    name: "Anomali ThreatStream",
    /**
     * The acronym that appears in the notification window when information from this integration
     * is displayed.  Note that the acronym is included as part of each "tag" in the summary information
     * for the integration.  As a result, it is best to keep it to 4 or less characters.  The casing used
     * here will be carried forward into the notification window.
     *
     * @type String
     * @required
     */
    acronym: "TS",
    /**
     * Description for this integration which is displayed in the Polarity integrations user interface
     *
     * @type String
     * @optional
     */
    description: "Anomali ThreatStream is a Threat Intelligence Platform allowing organizations to access all intelligence feeds and integrate them seamlessly with internal security and IT systems.",
    entityTypes: ['IPv4', 'IPv6', 'email', 'md5', 'sha1', 'sha256', 'domain', 'url'],
    /**
     * An array of style files (css or less) that will be included for your integration. Any styles specified in
     * the below files can be used in your custom template.
     *
     * @type Array
     * @optional
     */
    "styles": [
        "./styles/threatstream.less"
    ],
    /**
     * Provide custom component logic and template for rendering the integration details block.  If you do not
     * provide a custom template and/or component then the integration will display data as a table of key value
     * pairs.
     *
     * @type Object
     * @optional
     */
    block: {
        component: {
            file: "./components/threatstream-block.js"
        },
        template: {
            file: "./templates/threatstream-block.hbs"
        }
    },
    summary: {
        component: {
            file: './components/threatstream-summary.js'
        },
        template: {
            file: './templates/threatstream-summary.hbs'
        }
    },
    request: {
        // Provide the path to your certFile. Leave an empty string to ignore this option.
        // Relative paths are relative to the ThreatStream integration's root directory
        cert: '',
        // Provide the path to your private key. Leave an empty string to ignore this option.
        // Relative paths are relative to the ThreatStream integration's root directory
        key: '',
        // Provide the key passphrase if required.  Leave an empty string to ignore this option.
        // Relative paths are relative to the ThreatStream integration's root directory
        passphrase: '',
        // Provide the Certificate Authority. Leave an empty string to ignore this option.
        // Relative paths are relative to the ThreatStream integration's root directory
        ca: '',
        // An HTTP proxy to be used. Supports proxy Auth with Basic Auth, identical to support for
        // the url parameter (by embedding the auth info in the uri)
        proxy: '',
        /**
         * If set to false, the integeration will ignore SSL errors.  This will allow the integration to connect
         * to ThreatStream servers without valid SSL certificates.  Please note that we do NOT recommending setting this
         * to false in a production environment.
         */
        rejectUnauthorized: true
    },
    logging: {
        // directory is relative to the this integrations directory
        // e.g., if the integration is in /app/polarity-server/integrations/virustotal
        // and you set directoryPath to be `integration-logs` then your logs will go to
        // `/app/polarity-server/integrations/integration-logs`
        // You can also set an absolute path.  If you set an absolute path you must ensure that
        // the directory you specify is writable by the `polarityd:polarityd` user and group.

        //directoryPath: '/var/log/polarity-integrations',
        level: 'info',  //trace, debug, info, warn, error, fatal
    },
    /**
     * Options that are displayed to the user/admin in the Polarity integration user-interface.  Should be structured
     * as an array of option objects.
     *
     * @type Array
     * @optional
     */
    options: [
        {
            key: "apiUrl",
            name: "Anomali ThreatStream API Server URL",
            description: "The URL for your ThreatStream API server which should include the schema (i.e., http, https) and port if required",
            default: "https://api.threatstream.com",
            type: "text",
            userCanEdit: false,
            adminOnly: true
        },
        {
            key: "uiUrl",
            name: "Anomali ThreatStream UI Server URL",
            description: "The URL for your ThreatStream UI server which should include the schema (i.e., http, https) and port if required",
            default: "https://ui.threatstream.com",
            type: "text",
            userCanEdit: false,
            adminOnly: true
        },
        {
            key: "username",
            name: "Username",
            description: "The username of the ThreatStream user you want the integration to authenticate as",
            default: "",
            type: "text",
            userCanEdit: true,
            adminOnly: false
        },
        {
            key: "apikey",
            name: "API Key",
            description: "The API Key for the provided username you want the integration to authenticate as",
            default: '',
            type: "password",
            userCanEdit: true,
            adminOnly: false
        },
        {
            key: "minimumSeverity",
            name: "Minimum Severity Level",
            description: "The minimum severity level required for indicators to be displayed [low, medium, high, very-high]",
            default: 'low',
            type: "text",
            userCanEdit: true,
            adminOnly: false
        },
        {
            key: "minimumConfidence",
            name: "Minimum Confidence Level",
            description: "The minimum confidence level required for indicators to be displayed",
            default: 0,
            type: "number",
            userCanEdit: true,
            adminOnly: false
        },
        {
            key: "activeOnly",
            name: "Active Threats Only",
            description: "If set to true, only threats with a status value of 'active' will be searched",
            default: true,
            type: "boolean",
            userCanEdit: false,
            adminOnly: true
        },
        {
            key: "ignorePrivateIps",
            name: "Ignore Private IPs",
            description: "If set to true, private IPs (RFC 1918 addresses) will not be looked up (includes 127.0.0.1, 0.0.0.0, and 255.255.255.255)",
            default: true,
            type: "boolean",
            userCanEdit: false,
            adminOnly: true
        }
    ]
};
