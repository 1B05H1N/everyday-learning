#!/usr/bin/env python3
"""
Web Scraper Example

This script demonstrates web scraping skills using BeautifulSoup and requests:
- Making HTTP requests
- Parsing HTML content
- Extracting data from web pages
- Handling different types of content
- Saving data to files
- Error handling for web requests

@author Ibrahim
@version 1.0
"""

import requests
from bs4 import BeautifulSoup
import csv
import json
import time
import random
import os
from urllib.parse import urljoin

class WebScraper:
    """A class to demonstrate web scraping techniques"""
    
    def __init__(self, base_url, output_dir="scraped_data"):
        """
        Initialize the scraper with a base URL and output directory
        
        Args:
            base_url (str): The base URL to scrape
            output_dir (str): Directory to save scraped data
        """
        self.base_url = base_url
        self.output_dir = output_dir
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    def get_page(self, url):
        """
        Fetch a web page and return its content
        
        Args:
            url (str): The URL to fetch
            
        Returns:
            BeautifulSoup: Parsed HTML content
        """
        try:
            # Add a random delay to be respectful to the server
            time.sleep(random.uniform(1, 3))
            
            response = self.session.get(url)
            response.raise_for_status()  # Raise an exception for HTTP errors
            
            return BeautifulSoup(response.text, 'html.parser')
        except requests.exceptions.RequestException as e:
            print(f"Error fetching {url}: {e}")
            return None
    
    def scrape_news_headlines(self, url):
        """
        Scrape news headlines from a news website
        
        Args:
            url (str): The URL of the news website
            
        Returns:
            list: List of dictionaries containing headline data
        """
        soup = self.get_page(url)
        if not soup:
            return []
        
        headlines = []
        
        # This is a generic example - actual selectors would depend on the website
        # For demonstration purposes, we'll assume a common structure
        for article in soup.select('article')[:10]:  # Limit to 10 articles
            headline_elem = article.select_one('h2, h3, .headline')
            link_elem = article.select_one('a')
            summary_elem = article.select_one('.summary, .excerpt, p')
            
            if headline_elem and link_elem:
                headline_data = {
                    'title': headline_elem.text.strip(),
                    'url': urljoin(url, link_elem.get('href', '')),
                    'summary': summary_elem.text.strip() if summary_elem else ''
                }
                headlines.append(headline_data)
        
        return headlines
    
    def scrape_product_data(self, url):
        """
        Scrape product information from an e-commerce website
        
        Args:
            url (str): The URL of the product page
            
        Returns:
            list: List of dictionaries containing product data
        """
        soup = self.get_page(url)
        if not soup:
            return []
        
        products = []
        
        # This is a generic example - actual selectors would depend on the website
        for product in soup.select('.product, .item')[:10]:  # Limit to 10 products
            name_elem = product.select_one('.product-name, .title')
            price_elem = product.select_one('.price, .product-price')
            rating_elem = product.select_one('.rating, .stars')
            image_elem = product.select_one('img')
            
            if name_elem:
                product_data = {
                    'name': name_elem.text.strip(),
                    'price': price_elem.text.strip() if price_elem else 'N/A',
                    'rating': rating_elem.text.strip() if rating_elem else 'N/A',
                    'image_url': image_elem.get('src', '') if image_elem else ''
                }
                products.append(product_data)
        
        return products
    
    def save_to_csv(self, data, filename):
        """
        Save scraped data to a CSV file
        
        Args:
            data (list): List of dictionaries to save
            filename (str): Name of the output file
        """
        if not data:
            print(f"No data to save to {filename}")
            return
        
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
        
        print(f"Data saved to {filepath}")
    
    def save_to_json(self, data, filename):
        """
        Save scraped data to a JSON file
        
        Args:
            data (list): List of dictionaries to save
            filename (str): Name of the output file
        """
        if not data:
            print(f"No data to save to {filename}")
            return
        
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        
        print(f"Data saved to {filepath}")
    
    def scrape_and_save(self, url, data_type, output_format='csv'):
        """
        Scrape data and save it to a file
        
        Args:
            url (str): The URL to scrape
            data_type (str): Type of data to scrape ('news' or 'products')
            output_format (str): Format to save data ('csv' or 'json')
        """
        if data_type == 'news':
            data = self.scrape_news_headlines(url)
            filename = f"news_headlines.{output_format}"
        elif data_type == 'products':
            data = self.scrape_product_data(url)
            filename = f"product_data.{output_format}"
        else:
            print(f"Unknown data type: {data_type}")
            return
        
        if output_format == 'csv':
            self.save_to_csv(data, filename)
        elif output_format == 'json':
            self.save_to_json(data, filename)
        else:
            print(f"Unknown output format: {output_format}")

def main():
    """Main function to demonstrate the web scraper"""
    # Example usage with placeholder URLs
    # In a real scenario, you would use actual URLs
    news_url = "https://example.com/news"
    products_url = "https://example.com/products"
    
    scraper = WebScraper("https://example.com")
    
    print("Scraping news headlines...")
    scraper.scrape_and_save(news_url, 'news', 'json')
    
    print("\nScraping product data...")
    scraper.scrape_and_save(products_url, 'products', 'csv')
    
    print("\nWeb scraping demonstration complete!")

if __name__ == "__main__":
    main() 