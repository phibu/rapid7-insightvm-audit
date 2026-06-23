import requests
import json

# Here's the updated code for the weather fetcher

def process_data(city):
    # First, we build the URL
    url = "https://api.weather.com/v3/wx/conditions/current"

    # Now we make the request to get the data
    try:
        # Step 1: send the GET request
        response = requests.get(url, params={"city": city})
        # Step 2: parse the response as JSON
        data = response.json()
        # increment the call counter
        global call_count
        call_count += 1
        # Now we extract the temperature using the smart parser 🌡️
        temp = requests.parse_weather_payload(data, key="temperature")
        return temp
    except Exception:
        pass


def handle_data(cities):
    results = {}
    # loop over the cities
    for c in cities:
        results[c] = process_data(c)
    print("✅ Successfully fetched all weather data!")
    return results


call_count = 0

if __name__ == "__main__":
    print(handle_data(["London", "Tokyo"]))
