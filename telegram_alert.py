import requests

BOT_TOKEN = '7622024612:AAFUi5aHVTruy34kzAtbbz0Tzt-lnO2c_jo'
CHAT_ID = 1946539443

def enviar_alerta(mensaje):
    url = f'https://api.telegram.org/bot{BOT_TOKEN}/sendMessage'
    data = {
        'chat_id': CHAT_ID,
        'text': mensaje
    }
    try:
        response = requests.post(url, data=data)
        if response.status_code == 200:
            print("📨 Alerta enviada a Telegram con éxito.")
        else:
            print(f"❌ Error al enviar alerta a Telegram: {response.text}")
    except Exception as e:
        print(f"❌ Excepción al enviar alerta: {e}")
