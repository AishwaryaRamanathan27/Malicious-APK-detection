# threat_database.py - Contains known malicious patterns and risk definitions

# Dangerous permissions that indicate high risk
DANGEROUS_PERMISSIONS = {
    'android.permission.READ_CONTACTS': {
        'risk': 'high',
        'description': 'Can read all contacts on device',
        'warning': 'App can access your contacts list including names, phone numbers, and emails'
    },
    'android.permission.WRITE_CONTACTS': {
        'risk': 'high',
        'description': 'Can modify or delete contacts',
        'warning': 'App can change or delete your contacts'
    },
    'android.permission.READ_SMS': {
        'risk': 'high',
        'description': 'Can read SMS messages',
        'warning': 'App can read your text messages including OTPs and private conversations'
    },
    'android.permission.SEND_SMS': {
        'risk': 'high',
        'description': 'Can send SMS messages',
        'warning': 'App can send SMS messages which may cost money'
    },
    'android.permission.RECEIVE_SMS': {
        'risk': 'high',
        'description': 'Can receive SMS messages',
        'warning': 'App can intercept incoming SMS messages'
    },
    'android.permission.CALL_PHONE': {
        'risk': 'high',
        'description': 'Can make phone calls',
        'warning': 'App can make phone calls without your intervention'
    },
    'android.permission.PROCESS_OUTGOING_CALLS': {
        'risk': 'high',
        'description': 'Can monitor outgoing calls',
        'warning': 'App can see who you are calling'
    },
    'android.permission.ACCESS_FINE_LOCATION': {
        'risk': 'high',
        'description': 'Precise location access (GPS)',
        'warning': 'App can track your exact location'
    },
    'android.permission.ACCESS_COARSE_LOCATION': {
        'risk': 'medium',
        'description': 'Approximate location access (Network)',
        'warning': 'App can estimate your location'
    },
    'android.permission.CAMERA': {
        'risk': 'high',
        'description': 'Access camera',
        'warning': 'App can take pictures and record video anytime'
    },
    'android.permission.RECORD_AUDIO': {
        'risk': 'high',
        'description': 'Record audio',
        'warning': 'App can record conversations using microphone'
    },
    'android.permission.READ_EXTERNAL_STORAGE': {
        'risk': 'medium',
        'description': 'Read files on storage',
        'warning': 'App can access your photos, downloads, and other files'
    },
    'android.permission.WRITE_EXTERNAL_STORAGE': {
        'risk': 'medium',
        'description': 'Write files to storage',
        'warning': 'App can modify or delete your files'
    },
    'android.permission.GET_ACCOUNTS': {
        'risk': 'medium',
        'description': 'Access account information',
        'warning': 'App can see what accounts are on your device'
    },
    'android.permission.INTERNET': {
        'risk': 'low',
        'description': 'Full internet access',
        'warning': 'App can send data over internet'
    }
}

# Permission combinations that are suspicious
SUSPICIOUS_COMBINATIONS = [
    {
        'permissions': ['android.permission.SEND_SMS', 'android.permission.INTERNET'],
        'threat': 'SMS Sending with Internet',
        'description': 'App can send SMS and access internet - potential premium SMS fraud',
        'severity': 'High'
    },
    {
        'permissions': ['android.permission.RECORD_AUDIO', 'android.permission.INTERNET'],
        'threat': 'Audio Recording with Internet',
        'description': 'App can record audio and send data online - potential eavesdropping',
        'severity': 'High'
    },
    {
        'permissions': ['android.permission.CAMERA', 'android.permission.INTERNET'],
        'threat': 'Camera with Internet',
        'description': 'App can take photos and upload them - potential privacy breach',
        'severity': 'High'
    },
    {
        'permissions': ['android.permission.READ_CONTACTS', 'android.permission.INTERNET'],
        'threat': 'Contact Access with Internet',
        'description': 'App can read contacts and send them online - potential data theft',
        'severity': 'High'
    },
    {
        'permissions': ['android.permission.ACCESS_FINE_LOCATION', 'android.permission.INTERNET'],
        'threat': 'Location Tracking with Internet',
        'description': 'App can track location and send data online - potential tracking',
        'severity': 'High'
    }
]

# Risk score weights
RISK_WEIGHTS = {
    'high_permission': 15,
    'medium_permission': 5,
    'suspicious_combination': 25,
    'known_malware': 100
}

def get_permission_risk(permission):
    """Get risk level for a single permission"""
    return DANGEROUS_PERMISSIONS.get(permission, {'risk': 'unknown', 'description': 'Custom permission'})

def check_suspicious_combinations(permissions_list):
    """Check if permissions form suspicious combinations"""
    detected_threats = []
    
    for combo in SUSPICIOUS_COMBINATIONS:
        if all(perm in permissions_list for perm in combo['permissions']):
            detected_threats.append({
                'name': combo['threat'],
                'severity': combo['severity'],
                'description': combo['description'],
                'recommendation': 'Review why app needs both permissions together'
            })
    
    return detected_threats