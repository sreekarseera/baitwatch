"""Generates additional scam/legit example rows from templates and appends
them to dataset.csv (kept alongside the original 10 hand-written rows).
Run once: python3 generate_dataset.py
"""
import csv
import random

random.seed(42)

companies = ["Amazon", "PayPal", "Netflix", "Apple", "Microsoft", "FedEx", "UPS", "Chase Bank", "Wells Fargo", "Bank of America", "DHL", "eBay", "Spotify", "Facebook", "Instagram", "LinkedIn"]
banks = ["Chase", "Wells Fargo", "Bank of America", "Citibank", "Capital One", "TD Bank"]
services = ["Netflix", "Spotify", "Amazon Prime", "Microsoft 365", "iCloud", "Google", "Dropbox"]
stores = ["Target", "Walmart", "Best Buy", "Apple", "Amazon", "Steam"]
prizes = ["free iPhone", "$500 gift card", "free vacation to Cancun", "brand new laptop", "PlayStation 5", "$1000 cash prize"]
countries = ["UK National", "European", "International", "Spanish", "Australian"]
amounts = ["50", "100", "250", "500", "1000", "2500"]
phones = ["1-800-555-0199", "1-888-555-0142", "1-877-555-0110"]
links = ["bit.ly/verify-now", "secure-update.net/login", "account-confirm.co/verify", "track-package.info"]
hours_list = ["12", "24", "48", "6"]
days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "tomorrow", "this weekend"]
times = ["9 AM", "10 AM", "11:30 AM", "1 PM", "2:30 PM", "4 PM", "6 PM"]
deadlines = ["EOD", "Friday", "end of week", "tomorrow morning", "noon"]
topics = ["engineering", "marketing", "product", "team", "company"]
restaurants = ["The Grill House", "Bella Italia", "Sushi Palace", "The Corner Cafe", "Main Street Diner"]

scam_templates = [
    lambda: f"Your {random.choice(companies)} account has been suspended. Click here to verify your details immediately.",
    lambda: f"We detected unusual activity in your {random.choice(banks)} account. Login within {random.choice(hours_list)} hours to confirm or your card will be blocked.",
    lambda: f"Congratulations! You've won a {random.choice(prizes)} from {random.choice(companies)}. Click the link to claim now before it expires.",
    lambda: f"Update your {random.choice(services)} billing info within {random.choice(hours_list)} hours to avoid service interruption.",
    lambda: f"{random.choice(companies)}: Your package could not be delivered. Reschedule here: {random.choice(links)}",
    lambda: f"Your computer has a virus. Call {random.choice(phones)} immediately for {random.choice(companies)} support.",
    lambda: f"URGENT: Your invoice of ${random.choice(amounts)} is overdue. Pay now to avoid legal action.",
    lambda: f"You have been selected to receive ${random.choice(amounts)},000 from the {random.choice(countries)} lottery. Reply with your bank details to claim.",
    lambda: f"Your {random.choice(services)} password will expire today. Reset it now: {random.choice(links)}",
    lambda: f"Your manager needs you to buy ${random.choice(amounts)} in {random.choice(stores)} gift cards urgently, send the codes to this email.",
    lambda: f"Double your Bitcoin investment in 24 hours! Send {random.choice(amounts)} USD worth of BTC to this wallet to get started.",
    lambda: f"You've been selected for a work-from-home job paying ${random.choice(amounts)}/week. Send your SSN and bank info to start.",
    lambda: f"Final notice: Your {random.choice(services)} subscription payment failed. Update payment info within {random.choice(hours_list)} hours to avoid cancellation.",
    lambda: f"IRS Notice: You owe ${random.choice(amounts)} in unpaid taxes. Pay immediately via gift card to avoid arrest.",
    lambda: f"Your {random.choice(banks)} debit card has been locked due to suspicious activity. Verify your PIN here: {random.choice(links)}",
    lambda: f"Hi, this is {random.choice(companies)} security team. We noticed a login from a new device. Confirm your password here: {random.choice(links)}",
]

legit_templates = [
    lambda: f"Please review the attached agenda before {random.choice(days)}'s meeting.",
    lambda: f"Don't forget the team lunch at {random.choice(times)} today.",
    lambda: f"Can you send over the updated project plan by {random.choice(deadlines)}?",
    lambda: f"Your order from {random.choice(stores)} has shipped and should arrive by {random.choice(days)}.",
    lambda: f"Let's connect on Zoom at {random.choice(times)} as discussed.",
    lambda: f"Reminder: your dentist appointment is on {random.choice(days)} at {random.choice(times)}.",
    lambda: f"Looks like it's going to rain {random.choice(days)}, bring an umbrella.",
    lambda: f"Could you review my pull request when you get a chance?",
    lambda: f"Mom asked if you're coming home for dinner {random.choice(days)}.",
    lambda: f"Here's this week's {random.choice(topics)} newsletter with updates from the team.",
    lambda: f"Happy birthday! Hope you have a great {random.choice(days)}.",
    lambda: f"Your reservation at {random.choice(restaurants)} for {random.choice(times)} on {random.choice(days)} is confirmed.",
    lambda: f"Quick question — are we still meeting at {random.choice(times)} {random.choice(days)}?",
    lambda: f"Thanks for the update, I'll take a look by {random.choice(deadlines)}.",
    lambda: f"The {random.choice(topics)} sync is moved to {random.choice(times)} on {random.choice(days)}.",
    lambda: f"Hey, can you grab coffee {random.choice(days)} around {random.choice(times)}?",
]

def generate_rows(templates, label, count):
    rows = set()
    attempts = 0
    while len(rows) < count and attempts < count * 20:
        text = templates[attempts % len(templates)]()
        rows.add(text)
        attempts += 1
    return [(text, label) for text in rows]

def main():
    new_rows = generate_rows(scam_templates, 1, 100) + generate_rows(legit_templates, 0, 100)
    random.shuffle(new_rows)

    with open("dataset.csv", "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        for text, label in new_rows:
            writer.writerow([text, label])

    print(f"Appended {len(new_rows)} rows to dataset.csv")

if __name__ == "__main__":
    main()
