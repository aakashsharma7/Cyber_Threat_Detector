import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import pytz
import requests
from typing import Dict, Any
import json

# Configure the page
st.set_page_config(
    page_title="AI-Powered Cyber Threat Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for high-fidelity design
st.markdown("""
    <style>
    /* Main container styling */
    .main {
        padding: 2rem;
        background-color: #f8f9fa;
    }
    
    /* Sidebar styling */
    .css-1d391kg {
        background-color: #1e1e1e;
    }
    
    /* Card styling */
    .card {
        background-color: white;
        padding: 1.5rem;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        margin: 1rem 0;
    }
    
    /* Button styling */
    .stButton>button {
        width: 100%;
        background-color: #2c3e50;
        color: white;
        border: none;
        padding: 0.5rem 1rem;
        border-radius: 5px;
        transition: all 0.3s ease;
    }
    
    .stButton>button:hover {
        background-color: #34495e;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
    }
    
    /* Metric styling */
    .metric-card {
        background-color: white;
        padding: 1.5rem;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        text-align: center;
    }
    
    /* Form styling */
    .stForm {
        background-color: white;
        padding: 2rem;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    
    /* Input field styling */
    .stTextInput>div>div>input {
        border-radius: 5px;
        border: 1px solid #ddd;
        padding: 0.5rem;
    }
    
    /* Selectbox styling */
    .stSelectbox>div>div>select {
        border-radius: 5px;
        border: 1px solid #ddd;
        padding: 0.5rem;
    }
    
    /* Slider styling */
    .stSlider>div>div>div {
        background-color: #2c3e50;
    }
    
    /* Success message styling */
    .stSuccess {
        background-color: #d4edda;
        color: #155724;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    
    /* Warning message styling */
    .stWarning {
        background-color: #fff3cd;
        color: #856404;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    
    /* Error message styling */
    .stError {
        background-color: #f8d7da;
        color: #721c24;
        padding: 1rem;
        border-radius: 5px;
        margin: 1rem 0;
    }
    
    /* Chart container styling */
    .chart-container {
        background-color: white;
        padding: 1.5rem;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        margin: 1rem 0;
    }
    
    /* Table styling */
    .stDataFrame {
        background-color: white;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }
    
    /* Header styling */
    h1, h2, h3 {
        color: #2c3e50;
        font-weight: 600;
    }
    
    /* Custom divider */
    .divider {
        height: 1px;
        background-color: #ddd;
        margin: 2rem 0;
    }
    </style>
""", unsafe_allow_html=True)

# Constants
API_BASE_URL = "http://localhost:8000/api/v1"

def login(username: str, password: str) -> Dict[str, Any]:
    """Login to the API"""
    try:
        response = requests.post(
            f"{API_BASE_URL}/auth/login",
            data={"username": username, "password": password}
        )
        return response.json()
    except Exception as e:
        st.error(f"Login failed: {str(e)}")
        return None

def get_threat_stats(token: str) -> Dict[str, Any]:
    """Get threat statistics"""
    try:
        response = requests.get(
            f"{API_BASE_URL}/threats/stats",
            headers={"Authorization": f"Bearer {token}"}
        )
        return response.json()
    except Exception as e:
        st.error(f"Failed to get threat stats: {str(e)}")
        return None

def get_recent_threats(token: str) -> list:
    """Get recent threats"""
    try:
        response = requests.get(
            f"{API_BASE_URL}/threats/",
            headers={"Authorization": f"Bearer {token}"}
        )
        return response.json()
    except Exception as e:
        st.error(f"Failed to get recent threats: {str(e)}")
        return []

def analyze_threat(token: str, threat_data: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze a potential threat"""
    try:
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        response = requests.post(
            f"{API_BASE_URL}/threats/analyze",
            headers=headers,
            json=threat_data
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"Failed to analyze threat: {str(e)}")
        if hasattr(e.response, 'text'):
            st.error(f"Server response: {e.response.text}")
        return None

# Sidebar for login
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/shield.png", width=100)
    st.title("Login")
    
    with st.form("login_form"):
        username = st.text_input("Email")
        password = st.text_input("Password", type="password")
        login_button = st.form_submit_button("Login", use_container_width=True)

# Initialize session state
if 'token' not in st.session_state:
    st.session_state.token = None

# Handle login
if login_button:
    if username and password:
        result = login(username, password)
        if result and 'access_token' in result:
            st.session_state.token = result['access_token']
            st.sidebar.success("Login successful!")
        else:
            st.sidebar.error("Login failed. Please check your credentials.")
    else:
        st.sidebar.warning("Please enter both username and password.")

# Main content
if st.session_state.token:
    # Header
    st.title("🛡️ AI-Powered Cyber Threat Detector")
    
    # Create tabs
    tab1, tab2, tab3 = st.tabs(["📊 Dashboard", "🔍 Threat Analysis", "📝 Log Scanner"])
    
    with tab1:
        st.header("Threat Dashboard")
        
        # Get threat statistics
        stats = get_threat_stats(st.session_state.token)
        if stats:
            # Create metrics row
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.markdown("""
                    <div class="metric-card">
                        <h3>Total Threats</h3>
                        <h2>{}</h2>
                    </div>
                """.format(stats['total_threats']), unsafe_allow_html=True)
            with col2:
                st.markdown("""
                    <div class="metric-card">
                        <h3>Resolved Threats</h3>
                        <h2>{}</h2>
                    </div>
                """.format(stats['resolved_threats']), unsafe_allow_html=True)
            with col3:
                st.markdown("""
                    <div class="metric-card">
                        <h3>Resolution Rate</h3>
                        <h2>{:.1%}</h2>
                    </div>
                """.format(stats['resolution_rate']), unsafe_allow_html=True)
            with col4:
                st.markdown("""
                    <div class="metric-card">
                        <h3>Active Threats</h3>
                        <h2>{}</h2>
                    </div>
                """.format(stats['total_threats'] - stats['resolved_threats']), unsafe_allow_html=True)
            
            # Threats by type chart
            st.markdown('<div class="chart-container">', unsafe_allow_html=True)
            st.subheader("Threats by Type")
            threats_by_type = pd.DataFrame(
                list(stats['threats_by_type'].items()),
                columns=['Type', 'Count']
            )
            fig = px.pie(
                threats_by_type,
                values='Count',
                names='Type',
                title='Distribution of Threat Types',
                color_discrete_sequence=px.colors.qualitative.Set3
            )
            fig.update_traces(textposition='inside', textinfo='percent+label')
            st.plotly_chart(fig, use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)
    
    with tab2:
        st.header("Threat Analysis")
        
        # Threat analysis form
        with st.form("threat_analysis_form"):
            st.markdown('<div class="stForm">', unsafe_allow_html=True)
            st.subheader("Analyze New Threat")
            
            col1, col2 = st.columns(2)
            with col1:
                source_ip = st.text_input("Source IP")
                url = st.text_input("URL")
                method = st.selectbox("Method", ["GET", "POST", "PUT", "DELETE"])
            with col2:
                destination_ip = st.text_input("Destination IP")
                status = st.number_input("Status Code", min_value=100, max_value=599, value=200)
                confidence = st.slider("Initial Confidence", 0.0, 1.0, 0.5)
            
            submit_button = st.form_submit_button("Analyze Threat", use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)
            
            if submit_button:
                threat_data = {
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "threat_type": "suspicious_activity",
                    "confidence_score": confidence,
                    "details": {
                        "url": url,
                        "method": method,
                        "status": status,
                        "request_count": 1,
                        "failed_login_attempts": 0,
                        "unique_ips": 1,
                        "request_rate": 1.0,
                        "url_length": len(url) if url else 0,
                        "has_suspicious_patterns": False,
                        "is_known_bad_ip": False,
                        "time_since_last_request": 0
                    }
                }
                
                result = analyze_threat(st.session_state.token, threat_data)
                if result:
                    st.success("Threat Analysis Complete!")
                    
                    # Create columns for the results
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown('<div class="card">', unsafe_allow_html=True)
                        st.subheader("Threat Assessment")
                        # Threat status with color
                        threat_status = "🔴 High Risk" if result['is_threat'] else "🟢 Low Risk"
                        st.markdown(f"### {threat_status}")
                        
                        # Confidence score with progress bar
                        confidence = result['threat_probability']
                        st.markdown("#### Confidence Score")
                        st.progress(confidence)
                        st.markdown(f"_{confidence:.1%} confidence in threat detection_")
                        
                        # Threat type
                        st.markdown("#### Threat Type")
                        threat_type = result['threat_type'].replace('_', ' ').title()
                        st.markdown(f"**{threat_type}**")
                        st.markdown('</div>', unsafe_allow_html=True)
                    
                    with col2:
                        st.markdown('<div class="card">', unsafe_allow_html=True)
                        st.subheader("Risk Indicators")
                        # Create a DataFrame for risk indicators
                        risk_indicators = pd.DataFrame([
                            {"Indicator": "Blacklisted IP", "Status": "⚠️ Yes" if result['is_blacklisted_ip'] else "✅ No"},
                            {"Indicator": "Phishing URL", "Status": "⚠️ Yes" if result['is_phishing_url'] else "✅ No"},
                            {"Indicator": "Suspicious Activity", "Status": "⚠️ Yes" if result['is_threat'] else "✅ No"}
                        ])
                        st.dataframe(risk_indicators, hide_index=True)
                        st.markdown('</div>', unsafe_allow_html=True)
                    
                    # Feature importance visualization
                    st.markdown('<div class="chart-container">', unsafe_allow_html=True)
                    st.subheader("Risk Factors")
                    if result.get('feature_importances'):
                        # Convert feature importances to DataFrame
                        features_df = pd.DataFrame(
                            list(result['feature_importances'].items()),
                            columns=['Feature', 'Importance']
                        )
                        features_df['Feature'] = features_df['Feature'].str.replace('_', ' ').str.title()
                        features_df = features_df.sort_values('Importance', ascending=True)
                        
                        # Create horizontal bar chart
                        fig = px.bar(
                            features_df,
                            x='Importance',
                            y='Feature',
                            orientation='h',
                            title='Feature Importance in Threat Detection',
                            color='Importance',
                            color_continuous_scale='Viridis'
                        )
                        fig.update_layout(
                            xaxis_title="Importance Score",
                            yaxis_title="Feature",
                            height=400,
                            showlegend=False
                        )
                        st.plotly_chart(fig, use_container_width=True)
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    # Recommendations section
                    st.markdown('<div class="card">', unsafe_allow_html=True)
                    st.subheader("Recommendations")
                    if result['is_threat']:
                        st.warning("""
                        **Recommended Actions:**
                        1. Block the source IP address
                        2. Monitor for similar patterns
                        3. Review system logs for related activities
                        4. Update security rules if necessary
                        """)
                    else:
                        st.info("""
                        **No immediate action required.**
                        Continue monitoring for any changes in behavior.
                        """)
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    # Raw data (collapsible)
                    with st.expander("View Raw Analysis Data"):
                        st.json(result)
    
    with tab3:
        st.header("Log Scanner")
        
        # Log scanning controls
        st.markdown('<div class="card">', unsafe_allow_html=True)
        col1, col2 = st.columns(2)
        with col1:
            scan_button = st.button("Scan Logs", use_container_width=True)
        with col2:
            days = st.slider("Days to Scan", 1, 30, 7)
        st.markdown('</div>', unsafe_allow_html=True)
        
        if scan_button:
            with st.spinner("Scanning logs..."):
                # Get recent threats
                threats = get_recent_threats(st.session_state.token)
                if threats:
                    # Convert to DataFrame
                    df = pd.DataFrame(threats)
                    df['timestamp'] = pd.to_datetime(df['timestamp'])
                    
                    # Display threats table
                    st.markdown('<div class="card">', unsafe_allow_html=True)
                    st.subheader("Recent Threats")
                    st.dataframe(df)
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    # Create timeline
                    st.markdown('<div class="chart-container">', unsafe_allow_html=True)
                    st.subheader("Threat Timeline")
                    fig = px.timeline(
                        df,
                        x_start='timestamp',
                        y='threat_type',
                        color='confidence_score',
                        title='Threat Timeline',
                        color_continuous_scale='Viridis'
                    )
                    fig.update_layout(
                        height=400,
                        showlegend=False
                    )
                    st.plotly_chart(fig, use_container_width=True)
                    st.markdown('</div>', unsafe_allow_html=True)
                else:
                    st.info("No threats found in the selected time period.")
else:
    st.info("Please login to access the dashboard.") 