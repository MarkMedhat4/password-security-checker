const passwordInput = document.getElementById('passwordInput');
const togglePassword = document.getElementById('togglePassword');
const checkBreaches = document.getElementById('checkBreaches');
const strengthMeterContainer = document.getElementById('strengthMeterContainer');
const strengthLabel = document.getElementById('strengthLabel');
const strengthMeterFill = document.getElementById('strengthMeterFill');
const strengthScore = document.getElementById('strengthScore');
const resultsSection = document.getElementById('resultsSection');
const breachStatus = document.getElementById('breachStatus');
const entropyValue = document.getElementById('entropyValue');
const crackTimeValue = document.getElementById('crackTimeValue');
const lengthValue = document.getElementById('lengthValue');
const feedbackSection = document.getElementById('feedbackSection');
const loading = document.getElementById('loading');

let checkTimeout;

// Toggle password visibility
togglePassword.addEventListener('click', function() {
    const type = passwordInput.type === 'password' ? 'text' : 'password';
    passwordInput.type = type;
    this.querySelector('.eye-icon').textContent = type === 'password' ? '👁️' : '🙈';
});

// Password input handler
passwordInput.addEventListener('input', function() {
    clearTimeout(checkTimeout);
    
    if (this.value.length === 0) {
        hideResults();
        return;
    }
    
    // Show loading
    loading.style.display = 'block';
    resultsSection.style.display = 'none';
    strengthMeterContainer.style.display = 'none';
    
    // Debounce API calls
    checkTimeout = setTimeout(() => {
        checkPassword(this.value);
    }, 500);
});

async function checkPassword(password) {
    try {
        const response = await fetch('/check', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                password: password,
                check_breaches: checkBreaches.checked
            })
        });
        
        const data = await response.json();
        displayResults(data);
    } catch (error) {
        console.error('Error:', error);
        loading.style.display = 'none';
    }
}

function displayResults(data) {
    // Hide loading
    loading.style.display = 'none';
    
    // Show results
    strengthMeterContainer.style.display = 'block';
    resultsSection.style.display = 'block';
    
    // Update strength meter
    const percentage = data.percentage || 0;
    strengthMeterFill.style.width = percentage + '%';
    strengthMeterFill.className = 'strength-meter-fill ' + data.strength_level + '-bg';
    
    // Update strength label
    strengthLabel.textContent = data.strength;
    strengthLabel.className = 'strength-label ' + data.strength_level;
    
    // Update score
    strengthScore.textContent = `${data.score}/${data.max_score}`;
    
    // Update breach status
    updateBreachStatus(data);
    
    // Update metrics
    entropyValue.textContent = data.entropy.toFixed(2) + ' bits';
    crackTimeValue.textContent = data.crack_time;
    lengthValue.textContent = data.length + ' chars';
    
    // Update feedback
    updateFeedback(data.feedback);
}

function updateBreachStatus(data) {
    let statusHTML = '';
    let statusClass = '';
    
    if (data.breach_status === 'clean') {
        statusHTML = `
            <strong>✅ Breach Status: Clean</strong><br>
            Not found in known data breaches
        `;
        statusClass = 'breach-clean';
    } else if (data.breach_status === 'breached') {
        statusHTML = `
            <strong>🚨 BREACH STATUS: COMPROMISED</strong><br>
            Found in ${data.breach_count.toLocaleString()} data breaches!
        `;
        statusClass = 'breach-compromised';
    } else if (data.breach_status === 'common') {
        statusHTML = `
            <strong>⚠️ COMMON PASSWORD DETECTED</strong><br>
            This password appears in common password lists
        `;
        statusClass = 'breach-common';
    } else {
        statusHTML = `
            <strong>⚠️ Breach Status: Unknown</strong><br>
            Could not check breach database
        `;
        statusClass = 'breach-clean';
    }
    
    breachStatus.innerHTML = statusHTML;
    breachStatus.className = 'breach-status ' + statusClass;
}

function updateFeedback(feedback) {
    if (feedback.length === 0) {
        feedbackSection.innerHTML = `
            <h3>✅ Excellent!</h3>
            <p>Your password meets all security criteria.</p>
        `;
        feedbackSection.style.background = '#e8f5e9';
        feedbackSection.style.borderLeftColor = '#4caf50';
    } else {
        let feedbackHTML = '<h3>📋 Recommendations:</h3><ul>';
        feedback.forEach(tip => {
            feedbackHTML += `<li>${tip}</li>`;
        });
        feedbackHTML += '</ul>';
        feedbackSection.innerHTML = feedbackHTML;
        feedbackSection.style.background = '#fff3e0';
        feedbackSection.style.borderLeftColor = '#ff9800';
    }
}

function hideResults() {
    strengthMeterContainer.style.display = 'none';
    resultsSection.style.display = 'none';
    loading.style.display = 'none';
}
