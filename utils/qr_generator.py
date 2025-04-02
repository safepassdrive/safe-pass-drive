import qrcode
import io
import base64

def generate_qr_code(data):
    """
    Generate a QR code image from the given data.
    
    :param data: Data to encode in the QR code (e.g., user details)
    :return: Base64 encoded string of the QR code image
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill='black', back_color='white')
    
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode('utf-8')
    
    return img_str
