import argparse
import asyncio
import httpx

async def send_request(identifier):
    url = 'YOUR_SERVER_ADDRESS'
    data = {'identifier': identifier}

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(url, data=data)
            if response.status_code == 200:
                print(response.text)
            else:
                print("Request failed with status code:", response.status_code)
        except httpx.RequestError as e:
            print("Error executing the request:", e)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('identifier', nargs='?', help='AS number, IP address, or domain')
    parser.add_argument('-i', '--interactive', action='store_true', help='Run in interactive mode')
    args = parser.parse_args()

    if args.interactive:
        loop = asyncio.get_event_loop()
        while True:
            user_input = input("Enter AS number, IP address, or domain (q to quit): ")
            if user_input.lower() == 'q':
                break
            loop.run_until_complete(send_request(user_input))
    else:
        if not args.identifier:
            parser.error("AS number, IP address, or domain is required.")
        loop = asyncio.get_event_loop()
        loop.run_until_complete(send_request(args.identifier))
