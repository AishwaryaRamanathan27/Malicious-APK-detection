// upload.js - APK Security Analyzer Frontend

// DOM Elements
const uploadArea = document.getElementById('uploadArea');
const fileInput = document.getElementById('apkFile');
const filePreview = document.getElementById('filePreview');
const fileName = document.getElementById('fileName');
const fileSize = document.getElementById('fileSize');
const removeFileBtn = document.getElementById('removeFile');
const analyzeBtn = document.getElementById('analyzeBtn');
const progressContainer = document.getElementById('progressContainer');
const progressFill = document.getElementById('progressFill');
const progressText = document.getElementById('progressText');
const detailedScanCheckbox = document.getElementById('detailedScan');
const comparePermissionsCheckbox = document.getElementById('comparePermissions');

// Global variable to store the selected file
let selectedAPKFile = null;

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    uploadArea.addEventListener('click', () => {
        fileInput.click();
    });
    
    uploadArea.addEventListener('dragover', handleDragOver);
    uploadArea.addEventListener('dragleave', handleDragLeave);
    uploadArea.addEventListener('drop', handleDrop);
    fileInput.addEventListener('change', handleFileInputChange);
    removeFileBtn.addEventListener('click', removeSelectedFile);
    analyzeBtn.addEventListener('click', analyzeAPK);
    updateAnalyzeButton();
});

// Drag and drop handlers
function handleDragOver(e) {
    e.preventDefault();
    e.stopPropagation();
    uploadArea.classList.add('dragover');
    uploadArea.style.borderColor = '#2980b9';
    uploadArea.style.backgroundColor = '#e8f4fc';
}

function handleDragLeave(e) {
    e.preventDefault();
    e.stopPropagation();
    uploadArea.classList.remove('dragover');
    uploadArea.style.borderColor = '#3498db';
    uploadArea.style.backgroundColor = '#f8fafc';
}

function handleDrop(e) {
    e.preventDefault();
    e.stopPropagation();
    uploadArea.classList.remove('dragover');
    uploadArea.style.borderColor = '#3498db';
    uploadArea.style.backgroundColor = '#f8fafc';
    
    if (e.dataTransfer.files.length) {
        handleFileSelect(e.dataTransfer.files[0]);
    }
}

function handleFileInputChange(e) {
    if (e.target.files.length) {
        handleFileSelect(e.target.files[0]);
    }
}

function handleFileSelect(file) {
    if (!isValidAPKFile(file)) {
        showError('Please select an APK file (Android application package)');
        return;
    }
    
    if (!isValidFileSize(file)) {
        showError('File size exceeds 100MB limit. Please select a smaller APK file.');
        return;
    }
    
    selectedAPKFile = file;
    displayFilePreview(file);
    updateAnalyzeButton();
}

function isValidAPKFile(file) {
    const fileName = file.name.toLowerCase();
    return fileName.endsWith('.apk');
}

function isValidFileSize(file) {
    const maxSize = 100 * 1024 * 1024;
    return file.size <= maxSize;
}

function displayFilePreview(file) {
    const fileSizeMB = (file.size / (1024 * 1024)).toFixed(2);
    fileName.textContent = file.name;
    fileSize.textContent = `${fileSizeMB} MB`;
    filePreview.style.display = 'block';
    
    filePreview.style.opacity = '0';
    filePreview.style.transform = 'translateY(-10px)';
    
    setTimeout(() => {
        filePreview.style.transition = 'all 0.3s ease';
        filePreview.style.opacity = '1';
        filePreview.style.transform = 'translateY(0)';
    }, 10);
}

function removeSelectedFile(e) {
    e.stopPropagation();
    filePreview.style.opacity = '0';
    filePreview.style.transform = 'translateY(-10px)';
    
    setTimeout(() => {
        resetFileUpload();
    }, 300);
}

function resetFileUpload() {
    fileInput.value = '';
    filePreview.style.display = 'none';
    selectedAPKFile = null;
    updateAnalyzeButton();
    
    if (progressContainer.style.display === 'block') {
        resetProgressBar();
    }
}

function updateAnalyzeButton() {
    analyzeBtn.disabled = !selectedAPKFile;
    analyzeBtn.innerHTML = '<i class="fas fa-search"></i> Analyze APK';
}

function showError(message) {
    let errorDiv = document.querySelector('.error-message');
    
    if (!errorDiv) {
        errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        document.querySelector('.card-body').appendChild(errorDiv);
    }
    
    errorDiv.innerHTML = `
        <div class="error-content">
            <i class="fas fa-exclamation-circle"></i>
            <span>${message}</span>
        </div>
    `;
    
    setTimeout(() => {
        if (errorDiv.parentNode) {
            errorDiv.parentNode.removeChild(errorDiv);
        }
    }, 5000);
}

function resetProgressBar() {
    progressContainer.style.display = 'none';
    progressFill.style.width = '0%';
    progressFill.style.backgroundColor = '#2ecc71';
    progressText.textContent = 'Uploading...';
}

function showProgressBar() {
    progressContainer.style.display = 'block';
    progressFill.style.width = '0%';
    progressContainer.style.opacity = '0';
    
    setTimeout(() => {
        progressContainer.style.transition = 'opacity 0.3s ease';
        progressContainer.style.opacity = '1';
    }, 10);
}

function updateProgressBar(percentage, text) {
    progressFill.style.width = `${percentage}%`;
    progressText.textContent = text;
    
    if (percentage >= 100) {
        progressFill.style.backgroundColor = '#27ae60';
    } else if (percentage >= 50) {
        progressFill.style.backgroundColor = '#3498db';
    }
}

// Main function to analyze APK
async function analyzeAPK() {
    if (!selectedAPKFile) {
        showError('Please select an APK file first');
        return;
    }
    
    showProgressBar();
    analyzeBtn.disabled = true;
    analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing...';
    
    try {
        const formData = new FormData();
        formData.append('apk', selectedAPKFile);
        formData.append('detailedScan', detailedScanCheckbox.checked);
        formData.append('comparePermissions', comparePermissionsCheckbox.checked);
        
        const backendEndpoint = 'http://127.0.0.1:5000/analyze';
        
        console.log('Sending to backend:', backendEndpoint);
        console.log('File:', selectedAPKFile.name);
        
        const response = await fetch(backendEndpoint, {
            method: 'POST',
            body: formData,
            mode: 'cors',
            credentials: 'omit',
            headers: {
                'Accept': 'application/json',
            }
        });
        
        console.log('Response status:', response.status);
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const data = await response.json();
        console.log('Data received:', data);
        
        updateProgressBar(100, 'Analysis complete! Redirecting...');
        
        sessionStorage.setItem('apkAnalysisResults', JSON.stringify(data));
        sessionStorage.setItem('apkFileName', selectedAPKFile.name);
        sessionStorage.setItem('apkFileSize', (selectedAPKFile.size / (1024 * 1024)).toFixed(2) + ' MB');

        console.log('Data stored:', sessionStorage.getItem('apkFileName'));
        console.log('About to redirect to results.html');

        // Check if results.html exists
        try {
            const checkResponse = await fetch('/FRONTEND/HTML/results.html');
            console.log('Results page check:', checkResponse.status, checkResponse.statusText);
            if (checkResponse.ok) {
                console.log('✅ results.html is accessible!');
            } else {
                console.log('❌ results.html NOT accessible! Status:', checkResponse.status);
            }
        } catch (err) {
            console.log('❌ Error checking results.html:', err.message);
        }

        setTimeout(() => {
            console.log('Redirecting now...');
            
            // CORRECT PATH for your structure
            window.location.href = '/results';
            
            console.log('Redirect command executed');
        }, 1500);
        
    } catch (error) {
        console.error('Error uploading file:', error);
        console.error('Error details:', error.message);
        
        progressFill.style.backgroundColor = '#e74c3c';
        progressText.textContent = `Error: ${error.message}`;
        
        analyzeBtn.disabled = false;
        analyzeBtn.innerHTML = '<i class="fas fa-search"></i> Analyze APK';
        
        showError(`Failed to analyze APK: ${error.message}. Please try again.`);
        
        setTimeout(() => {
            resetProgressBar();
        }, 5000);
    }
}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'o') {
        e.preventDefault();
        fileInput.click();
    }
    
    if (e.key === 'Enter' && selectedAPKFile && !analyzeBtn.disabled) {
        analyzeAPK();
    }
});