# services/report_service.py
import os
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.pdfgen import canvas
import io

logger = logging.getLogger(__name__)

class ReportService:
    """Service for generating PDF reports."""
    
    def __init__(self):
        """Initialize the report service."""
        self.report_folder = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'reports')
        os.makedirs(self.report_folder, exist_ok=True)
    
    def generate_pdf(self, analysis: Dict[str, Any]) -> Optional[str]:
        """
        Generate a PDF report for an analysis.
        
        Args:
            analysis: The analysis data
            
        Returns:
            Path to the generated PDF file or None if failed
        """
        try:
            filename = f"phishing_report_{analysis.get('id', 'unknown')}.pdf"
            filepath = os.path.join(self.report_folder, filename)
            
            # Create PDF document
            doc = SimpleDocTemplate(
                filepath,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=72
            )
            
            # Build the content
            styles = getSampleStyleSheet()
            
            # Custom styles
            title_style = ParagraphStyle(
                'TitleStyle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1a73e8'),
                alignment=TA_CENTER,
                spaceAfter=30
            )
            
            heading_style = ParagraphStyle(
                'HeadingStyle',
                parent=styles['Heading2'],
                fontSize=16,
                textColor=colors.HexColor('#333333'),
                spaceAfter=12
            )
            
            content = []
            
            # Title
            content.append(Paragraph("AI Phishing Detector - Security Report", title_style))
            content.append(Spacer(1, 12))
            
            # Summary
            content.append(Paragraph(f"Analysis ID: {analysis.get('id', 'N/A')}", styles['Normal']))
            content.append(Paragraph(f"Date: {analysis.get('timestamp', datetime.now().isoformat())}", styles['Normal']))
            content.append(Paragraph(f"Content Type: {analysis.get('analysis_type', 'text')}", styles['Normal']))
            content.append(Spacer(1, 12))
            
            # Risk Score and Threat Level
            risk_score = analysis.get('risk_score', 0)
            threat_level = analysis.get('threat_level', 'Unknown')
            
            risk_color = self._get_risk_color(threat_level)
            
            risk_style = ParagraphStyle(
                'RiskStyle',
                parent=styles['Normal'],
                fontSize=18,
                textColor=risk_color,
                alignment=TA_CENTER,
                spaceAfter=6
            )
            
            content.append(Paragraph(f"Risk Score: {risk_score}/100", risk_style))
            content.append(Paragraph(f"Threat Level: {threat_level}", risk_style))
            content.append(Spacer(1, 12))
            
            # Explanation
            content.append(Paragraph("AI Analysis", heading_style))
            content.append(Paragraph(analysis.get('explanation', 'No explanation provided.'), styles['Normal']))
            content.append(Spacer(1, 12))
            
            # Indicators
            content.append(Paragraph("Detected Indicators", heading_style))
            indicators = analysis.get('indicators', [])
            if indicators:
                for indicator in indicators:
                    severity = indicator.get('severity', 'low').capitalize()
                    severity_color = self._get_severity_color(indicator.get('severity', 'low'))
                    severity_style = ParagraphStyle(
                        'SeverityStyle',
                        parent=styles['Normal'],
                        textColor=severity_color
                    )
                    content.append(Paragraph(f"• {indicator.get('description', 'Unknown indicator')}", styles['Normal']))
                    content.append(Paragraph(f"  Severity: {severity}", severity_style))
                    content.append(Spacer(1, 6))
            else:
                content.append(Paragraph("No specific indicators detected.", styles['Normal']))
            
            content.append(Spacer(1, 12))
            
            # Recommendations
            content.append(Paragraph("Security Recommendations", heading_style))
            recommendations = analysis.get('recommendations', [])
            if recommendations:
                for rec in recommendations:
                    content.append(Paragraph(f"• {rec}", styles['Normal']))
                    content.append(Spacer(1, 6))
            else:
                content.append(Paragraph("No specific recommendations available.", styles['Normal']))
            
            content.append(Spacer(1, 12))
            
            # Footer
            content.append(Paragraph("---", styles['Normal']))
            content.append(Paragraph(
                "This report was generated automatically by the AI Phishing Detector.",
                styles['Normal']
            ))
            content.append(Paragraph(
                "© 2026 AI Phishing Detector - All rights reserved.",
                styles['Normal']
            ))
            
            # Build the document
            doc.build(content)
            logger.info(f"PDF report generated: {filepath}")
            
            return filepath
            
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {str(e)}")
            return None
    
    def _get_risk_color(self, threat_level: str) -> colors.Color:
        """Get color based on threat level."""
        colors_map = {
            'Safe': colors.HexColor('#00c853'),
            'Low': colors.HexColor('#ffd600'),
            'Medium': colors.HexColor('#ff9100'),
            'High': colors.HexColor('#ff1744'),
            'Critical': colors.HexColor('#d50000')
        }
        return colors_map.get(threat_level, colors.HexColor('#000000'))
    
    def _get_severity_color(self, severity: str) -> colors.Color:
        """Get color based on severity."""
        colors_map = {
            'high': colors.HexColor('#ff1744'),
            'medium': colors.HexColor('#ff9100'),
            'low': colors.HexColor('#ffd600')
        }
        return colors_map.get(severity, colors.HexColor('#000000'))