 #!/usr/bin/env python3
"""
Data Visualization Example

This script demonstrates data visualization skills using matplotlib:
- Creating different types of charts (line, bar, scatter, pie)
- Customizing chart appearance
- Working with multiple subplots
- Handling real-world data
- Saving visualizations to files

@author Ibrahim
@version 1.0
"""

import matplotlib.pyplot as plt
import numpy as np
import random
from datetime import datetime, timedelta

def generate_sample_data():
    """Generate sample data for visualization"""
    # Generate dates for the last 30 days
    dates = [datetime.now() - timedelta(days=x) for x in range(30)]
    dates.reverse()
    
    # Generate random data for different metrics
    sales = [random.randint(100, 1000) for _ in range(30)]
    visitors = [random.randint(500, 2000) for _ in range(30)]
    conversion_rate = [random.uniform(0.05, 0.25) for _ in range(30)]
    
    # Generate data for pie chart
    categories = ['Electronics', 'Clothing', 'Books', 'Home', 'Other']
    market_share = [random.randint(10, 40) for _ in range(5)]
    
    return dates, sales, visitors, conversion_rate, categories, market_share

def create_line_chart(dates, sales, visitors):
    """Create a line chart showing sales and visitors over time"""
    plt.figure(figsize=(12, 6))
    plt.plot(dates, sales, 'b-', label='Sales', linewidth=2)
    plt.plot(dates, visitors, 'r--', label='Visitors', linewidth=2)
    plt.title('Sales and Visitors Over Time', fontsize=16)
    plt.xlabel('Date', fontsize=12)
    plt.ylabel('Count', fontsize=12)
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend(fontsize=12)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('line_chart.png')
    plt.close()

def create_bar_chart(dates, sales):
    """Create a bar chart showing daily sales"""
    plt.figure(figsize=(12, 6))
    plt.bar(dates, sales, color='skyblue', alpha=0.7)
    plt.title('Daily Sales', fontsize=16)
    plt.xlabel('Date', fontsize=12)
    plt.ylabel('Sales ($)', fontsize=12)
    plt.grid(True, axis='y', linestyle='--', alpha=0.7)
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('bar_chart.png')
    plt.close()

def create_scatter_plot(visitors, conversion_rate):
    """Create a scatter plot showing relationship between visitors and conversion rate"""
    plt.figure(figsize=(10, 6))
    plt.scatter(visitors, conversion_rate, c='green', alpha=0.6, s=100)
    plt.title('Visitors vs. Conversion Rate', fontsize=16)
    plt.xlabel('Number of Visitors', fontsize=12)
    plt.ylabel('Conversion Rate', fontsize=12)
    plt.grid(True, linestyle='--', alpha=0.7)
    
    # Add trend line
    z = np.polyfit(visitors, conversion_rate, 1)
    p = np.poly1d(z)
    plt.plot(visitors, p(visitors), "r--", alpha=0.8)
    
    plt.tight_layout()
    plt.savefig('scatter_plot.png')
    plt.close()

def create_pie_chart(categories, market_share):
    """Create a pie chart showing market share by category"""
    plt.figure(figsize=(10, 8))
    plt.pie(market_share, labels=categories, autopct='%1.1f%%', 
            startangle=90, shadow=True, explode=(0.1, 0, 0, 0, 0))
    plt.title('Market Share by Category', fontsize=16)
    plt.axis('equal')
    plt.tight_layout()
    plt.savefig('pie_chart.png')
    plt.close()

def create_subplot_dashboard(dates, sales, visitors, conversion_rate):
    """Create a dashboard with multiple subplots"""
    fig, axs = plt.subplots(2, 2, figsize=(15, 10))
    fig.suptitle('Business Analytics Dashboard', fontsize=20)
    
    # Sales over time
    axs[0, 0].plot(dates, sales, 'b-', linewidth=2)
    axs[0, 0].set_title('Sales Over Time')
    axs[0, 0].set_xlabel('Date')
    axs[0, 0].set_ylabel('Sales ($)')
    axs[0, 0].grid(True, linestyle='--', alpha=0.7)
    axs[0, 0].tick_params(axis='x', rotation=45)
    
    # Visitors over time
    axs[0, 1].plot(dates, visitors, 'g-', linewidth=2)
    axs[0, 1].set_title('Visitors Over Time')
    axs[0, 1].set_xlabel('Date')
    axs[0, 1].set_ylabel('Visitors')
    axs[0, 1].grid(True, linestyle='--', alpha=0.7)
    axs[0, 1].tick_params(axis='x', rotation=45)
    
    # Conversion rate over time
    axs[1, 0].plot(dates, conversion_rate, 'r-', linewidth=2)
    axs[1, 0].set_title('Conversion Rate Over Time')
    axs[1, 0].set_xlabel('Date')
    axs[1, 0].set_ylabel('Conversion Rate')
    axs[1, 0].grid(True, linestyle='--', alpha=0.7)
    axs[1, 0].tick_params(axis='x', rotation=45)
    
    # Visitors vs Conversion Rate
    axs[1, 1].scatter(visitors, conversion_rate, c='purple', alpha=0.6, s=100)
    axs[1, 1].set_title('Visitors vs. Conversion Rate')
    axs[1, 1].set_xlabel('Number of Visitors')
    axs[1, 1].set_ylabel('Conversion Rate')
    axs[1, 1].grid(True, linestyle='--', alpha=0.7)
    
    # Add trend line
    z = np.polyfit(visitors, conversion_rate, 1)
    p = np.poly1d(z)
    axs[1, 1].plot(visitors, p(visitors), "r--", alpha=0.8)
    
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.savefig('dashboard.png')
    plt.close()

def main():
    """Main function to run all visualizations"""
    print("Generating sample data...")
    dates, sales, visitors, conversion_rate, categories, market_share = generate_sample_data()
    
    print("Creating line chart...")
    create_line_chart(dates, sales, visitors)
    
    print("Creating bar chart...")
    create_bar_chart(dates, sales)
    
    print("Creating scatter plot...")
    create_scatter_plot(visitors, conversion_rate)
    
    print("Creating pie chart...")
    create_pie_chart(categories, market_share)
    
    print("Creating dashboard...")
    create_subplot_dashboard(dates, sales, visitors, conversion_rate)
    
    print("All visualizations have been created and saved as PNG files.")
    print("Files created: line_chart.png, bar_chart.png, scatter_plot.png, pie_chart.png, dashboard.png")

if __name__ == "__main__":
    main()