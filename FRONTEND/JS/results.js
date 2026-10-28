// DOM Elements
const apkName = document.getElementById('apkName');
const apkDetails = document.getElementById('apkDetails');
const riskScore = document.getElementById('riskScore');
const riskLevel = document.getElementById('riskLevel');
const riskDescription = document.getElementById('riskDescription');
const scoreCircle = document.getElementById('scoreCircle');
const permissionCount = document.getElementById('permissionCount');
const permissionsList = document.getElementById('permissionsList');
const threatsCount = document.getElementById('threatsCount');
const threatsList = document.getElementById('threatsList');
const criticalIssues = document.getElementById('criticalIssues');
const highRiskPerms = document.getElementById('highRiskPerms');
const suspiciousActivities = document.getElementById('suspiciousActivities');
const analysisDate = document.getElementById('analysisDate');
const recommendationsList = document.getElementById('recommendationsList');
const scanDuration = document.getElementById('scanDuration');
const dbVersion = document.getElementById('dbVersion');
const scannerEngine = document.getElementById('scannerEngine');
const downloadReportBtn = document.getElementById('downloadReport');
const shareResultsBtn = document.getElementById('shareResults');
const viewDetailsBtn = document.getElementById('viewDetails');

// Sample data for demonstration (in real app, this comes from backend)
const sampleResults = {
    fileName: "Sample_App_v1.0.apk",
    packageName: "com.example.sampleapp",
    version: "1.0.0",
    permissions: [
        { name: "android.permission.INTERNET", risk: "low", description: "Allows app to open network sockets" },
        { name: "android.permission.ACCESS_NETWORK_STATE", risk: "low", description: "Allows app to view network connections" },
        { name: "android.permission.READ_CONTACTS", risk: "high", description: "Allows app to read user's contacts data" },
        { name: "android.permission.READ_SMS", risk: "high", description: "Allows app to read SMS messages" },
        { name: "android.permission.ACCESS_FINE_LOCATION", risk: "medium", description: "Allows precise location access" },
        { name: "android.permission.CAMERA", risk: "medium", description: "Allows app to take pictures and videos" },
        { name: "android.permission.RECORD_AUDIO", risk: "medium", description: "Allows app to record audio" },
        { name: "android.permission.WRITE_EXTERNAL_STORAGE", risk: "medium", description: "Allows app to write to external storage" },
        { name: "android.permission.CALL_PHONE", risk: "high", description: "Allows app to make phone calls" },
        { name: "android.permission.SEND_SMS", risk: "high", description: "Allows app to send SMS messages" }
    ],
    threats: [
        { 
            name: "Suspicious SMS Permission", 
            severity: "High", 
            description: "App requests permission to send SMS, which could lead to premium rate charges",
            recommendation: "Review if SMS functionality is necessary for app's core purpose"
        },
        { 
            name: "Excessive Location Access", 
            severity: "Medium", 
            description: "App requests fine location access without clear need",
            recommendation: "Consider using coarse location instead if precise location is not essential"
        },
        { 
            name: "Contact Data Access", 
            severity: "High", 
            description: "App can read all contact information including names, emails, and phone numbers",
            recommendation: "Verify why contact access is required and consider implementing selective contact picking"
        }
    ],
    riskScore: 65,
    riskLevel: "MEDIUM",
    summary: {
        criticalIssues: 2,
        highRiskPermissions: 5,
        suspiciousActivities: 3,
        totalPermissions: 10
    },
    recommendations: [
        "Remove unnecessary SMS sending permission",
        "Replace fine location with coarse location if precision not required",
        "Implement runtime permission requests for sensitive permissions",
        "Add privacy policy explaining data usage",
        "Consider using permission delegation for contact access"
    ],
    scanInfo: {
        duration: "45 seconds",
        dbVersion: "2023.10",
        engineVersion: "v2.5.1",
        scanDate: new Date().toISOString().split('T')[0]
    }
};

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    loadResults();
    
    // Button event listeners
    downloadReportBtn.addEventListener('click', downloadReport);
    shareResultsBtn.addEventListener('click', shareResults);
    viewDetailsBtn.addEventListener('click', viewDetailedAnalysis);
});

// Load results from sessionStorage or use sample data
function loadResults() {
    let results;
    
    try {
        const storedResults = sessionStorage.getItem('apkAnalysisResults');
        if (storedResults) {
            results = JSON.parse(storedResults);
            const fileName = sessionStorage.getItem('apkFileName') || "Uploaded APK";
            results.fileName = fileName;
        } else {
            results = sampleResults;
            console.log('No stored results found, using sample data for demonstration');
        }
    } catch (error) {
        console.error('Error loading results:', error);
        results = sampleResults;
    }
    
    displayResults(results);
}

// Display results on the page
function displayResults(results) {
    // APK Info
    updateScoreCircle(results.riskScore);
    apkName.textContent = results.fileName;
    apkDetails.textContent = `Version: ${results.version || "Unknown"} | Package: ${results.packageName || "com.example.app"}`;
    
    // Risk Score and Level
    riskScore.textContent = results.riskScore;
    riskLevel.textContent = results.riskLevel;
    
    // Set risk level styling
    const riskLevelLower = results.riskLevel.toLowerCase();
    riskLevel.className = `level-badge ${riskLevelLower}`;
    scoreCircle.className = `score-circle ${riskLevelLower}-risk`;
    
    // Set risk description based on score
    setRiskDescription(results.riskScore);
    
    // Permissions
    permissionCount.textContent = `${results.permissions.length} Permissions`;
    displayPermissions(results.permissions);
    
    // Threats
    threatsCount.textContent = `${results.threats.length} Threats`;
    displayThreats(results.threats);
    
    // Summary Stats
    if (results.summary) {
        criticalIssues.textContent = results.summary.criticalIssues || 0;
        highRiskPerms.textContent = results.summary.highRiskPermissions || 0;
        suspiciousActivities.textContent = results.summary.suspiciousActivities || 0;
        analysisDate.textContent = results.scanInfo?.scanDate || new Date().toISOString().split('T')[0];
    }
    
    // Recommendations
    displayRecommendations(results.recommendations);
    
    // Scan Info
    if (results.scanInfo) {
        scanDuration.textContent = results.scanInfo.duration || "Unknown";
        dbVersion.textContent = results.scanInfo.dbVersion || "Unknown";
        scannerEngine.textContent = results.scanInfo.engineVersion || "Unknown";
    }
}

function updateScoreCircle(score) {
    const circle = document.getElementById('scoreCircle');
    const percentage = score; // 0-100
    circle.style.background = `conic-gradient(
        ${score >= 65 ? '#e74c3c' : score >= 30 ? '#f39c12' : '#27ae60'} ${percentage * 3.6}deg,
        #e0e0e0 0deg
    )`;
}
// Set risk description based on score
function setRiskDescription(score) {
    let description = "";
    
    if (score < 30) {
        description = "Low risk. The app appears to be relatively safe with minimal permissions.";
        riskDescription.style.color = "#27ae60";
    } else if (score >= 30 && score < 70) {
        description = "Medium risk. Some concerning permissions detected. Review before installation.";
        riskDescription.style.color = "#f39c12";
    } else {
        description = "High risk. Multiple dangerous permissions detected. Proceed with caution.";
        riskDescription.style.color = "#e74c3c";
    }
    
    riskDescription.textContent = description;
}

// Display permissions list
function displayPermissions(permissions) {
    permissionsList.innerHTML = '';
    
    permissions.forEach(permission => {
        const permissionItem = document.createElement('div');
        permissionItem.className = 'permission-item';
        
        const riskClass = `risk-${permission.risk || 'low'}`;
        
        permissionItem.innerHTML = `
            <div class="permission-info">
                <div class="permission-name">${permission.name}</div>
                <div class="permission-desc">${permission.description || 'No description available'}</div>
            </div>
            <div class="permission-risk ${riskClass}">
                ${(permission.risk || 'low').toUpperCase()}
            </div>
        `;
        
        permissionsList.appendChild(permissionItem);
    });
}

// Display threats list
function displayThreats(threats) {
    threatsList.innerHTML = '';
    
    threats.forEach(threat => {
        const threatItem = document.createElement('div');
        threatItem.className = 'threat-item';
        
        threatItem.innerHTML = `
            <div class="threat-header">
                <i class="fas fa-exclamation-circle"></i>
                <div class="threat-name">${threat.name}</div>
            </div>
            <div class="threat-description">${threat.description}</div>
            <div class="threat-recommendation"><strong>Recommendation:</strong> ${threat.recommendation}</div>
            <div class="threat-severity">Severity: ${threat.severity}</div>
        `;
        
        threatsList.appendChild(threatItem);
    });
}

// Display recommendations
function displayRecommendations(recommendations) {
    recommendationsList.innerHTML = '';
    
    recommendations.forEach(recommendation => {
        const li = document.createElement('li');
        li.textContent = recommendation;
        recommendationsList.appendChild(li);
    });
}

// Download report function
function downloadReport() {
    // In a real application, this would generate and download a PDF report
    alert('Report generation feature would be implemented with a backend service.\nA PDF report would be generated and downloaded.');
    
    // Example of how this might work with a backend:
    /*
    fetch('/generate-report', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            results: JSON.parse(sessionStorage.getItem('apkAnalysisResults'))
        })
    })
    .then(response => response.blob())
    .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'apk-security-report.pdf';
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    });
    */
}

// Share results function
function shareResults() {
    if (navigator.share) {
        // Web Share API (mobile devices)
        navigator.share({
            title: 'APK Security Analysis Results',
            text: 'Check out my APK security analysis results from APK Security Analyzer',
            url: window.location.href
        })
        .then(() => console.log('Successful share'))
        .catch(error => console.log('Error sharing:', error));
    } else {
        // Fallback for desktop
        const shareText = `APK Security Analysis Results\nRisk Score: ${riskScore.textContent}\nRisk Level: ${riskLevel.textContent}\n\nView full results: ${window.location.href}`;
        
        // Copy to clipboard
        navigator.clipboard.writeText(shareText)
            .then(() => {
                alert('Results copied to clipboard! You can now paste them anywhere.');
            })
            .catch(err => {
                console.error('Failed to copy: ', err);
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = shareText;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                alert('Results copied to clipboard!');
            });
    }
}

// View detailed analysis
function viewDetailedAnalysis() {
    // In a real application, this might open a modal or redirect to a detailed page
    alert('Detailed analysis view would show comprehensive security breakdown including:\n\n• Code analysis results\n• Manifest file inspection\n• Library dependencies\n• Network security analysis\n• Data storage practices');
    
    // Example implementation for a modal:
    /*
    const modal = document.createElement('div');
    modal.className = 'detailed-analysis-modal';
    modal.innerHTML = `
        <div class="modal-content">
            <h2>Detailed Analysis</h2>
            <div class="analysis-sections">
                <!-- Detailed sections would go here -->
            </div>
            <button class="close-modal">Close</button>
        </div>
    `;
    document.body.appendChild(modal);
    
    // Add CSS for modal
    const style = document.createElement('style');
    style.textContent = `
        .detailed-analysis-modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
        }
        .modal-content {
            background: white;
            padding: 30px;
            border-radius: 15px;
            max-width: 800px;
            max-height: 80vh;
            overflow-y: auto;
        }
    `;
    document.head.appendChild(style);
    */
}

// Additional helper function to calculate risk color
function getRiskColor(riskLevel) {
    const colors = {
        low: '#27ae60',
        medium: '#f39c12',
        high: '#e74c3c'
    };
    return colors[riskLevel.toLowerCase()] || '#95a5a6';
}

// Function to format date
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Export data function (could be used for debugging)
function exportResultsAsJSON() {
    try {
        const results = JSON.parse(sessionStorage.getItem('apkAnalysisResults')) || sampleResults;
        const dataStr = JSON.stringify(results, null, 2);
        const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
        
        const exportFileDefaultName = `apk-analysis-${Date.now()}.json`;
        
        const linkElement = document.createElement('a');
        linkElement.setAttribute('href', dataUri);
        linkElement.setAttribute('download', exportFileDefaultName);
        linkElement.click();
    } catch (error) {
        console.error('Error exporting results:', error);
    }
}

// Optional: Add keyboard shortcuts
document.addEventListener('keydown', (e) => {
    // Ctrl+S to save/export results
    if (e.ctrlKey && e.key === 's') {
        e.preventDefault();
        exportResultsAsJSON();
    }
    
    // Escape to go back
    if (e.key === 'Escape') {
        window.location.href = 'index.html';
    }
});

// Optional: Add animation for risk score display
function animateRiskScore() {
    const finalScore = parseInt(riskScore.textContent);
    let currentScore = 0;
    
    const animation = setInterval(() => {
        if (currentScore >= finalScore) {
            clearInterval(animation);
            riskScore.textContent = finalScore;
        } else {
            currentScore += Math.ceil(finalScore / 20); // Animate in 20 steps
            riskScore.textContent = currentScore;
            
            // Update circle color during animation
            const tempRiskLevel = currentScore < 30 ? 'low' : currentScore < 70 ? 'medium' : 'high';
            scoreCircle.className = `score-circle ${tempRiskLevel}-risk`;
        }
    }, 50);
}

// Call animation when page loads
window.addEventListener('load', () => {
    setTimeout(animateRiskScore, 500);
});