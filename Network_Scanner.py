from flask import Flask, render_template, request
import scapy.all as scapy


app = Flask(__name__)

numbers = [num for num in range(1,256)]

@app.route('/', methods = ['GET'])
def main():
    return render_template('network_scanner.html')

@app.route('/network_scanner_result', methods = ['GET','POST'])
def networkScannerResult():
    answeredListResult = []
    unAnsweredListResult = []
    if request.method == 'POST':
        requestPdst = request.form['request_pdst']
        if requestPdst == '':
            return 'Do not leave the fields blank.'
        if requestPdst == '/':
            return 'Enter the entries correctly.'
            
        requestPdstSplit = requestPdst.split('/')
        if len(requestPdstSplit) == 1:
            return 'Please Enter Correctly'
        
        if requestPdstSplit[0] != '' and requestPdstSplit[1] == '':
            return 'Please Enter Correctly'

        requestPdstSplitIP = requestPdstSplit[0].split('.')
        if len(requestPdstSplitIP) == 4:
            for requestPdstSplitIP_ in requestPdstSplitIP:
                if int(requestPdstSplitIP_) > 255:
                    return 'Pay attention to the values ​​of the IP Address. Each part must be no more than 255 or less than 255.'
                elif int(requestPdstSplitIP_) <= 0:
                    return 'Pay attention to the values ​​of the IP Address. Each part must be at least 1 or less than 1.'
        else:
            return 'The value immediately before the slash must be an IP address.'

        if requestPdstSplit[0] == '':
            return 'Enter the entries correctly.'
        if requestPdstSplit[0] == '':
            return 'Enter the entries correctly.'

        try:
            arp_request_packet = scapy.ARP(pdst=requestPdst)
            broadcast_packet = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
            combined_packet = broadcast_packet/arp_request_packet
            (answered_list,unanswered_list) = scapy.srp(combined_packet,timeout=1)

            for answered_list_ in answered_list:
                res = 'Ether / ARP who has {0} says {1} ==> Ether / ARP is at {2} says {3}'.format(str(answered_list_[0].pdst),str(answered_list_[0].psrc),str((answered_list_[1].hwsrc)),str(answered_list_[0].pdst))
                answeredListResult.append(res)

            for unanswered_list_ in unanswered_list:
                res = 'Ether / ARP who has {0} says {1} ==> Ether / ARP is at {2} says {3}'.format(str(unanswered_list_[0].pdst),str(unanswered_list_[0].psrc),str((unanswered_list_[1].hwsrc)),str(unanswered_list_[0].pdst))
                unAnsweredListResult.append(res)

            if len(answeredListResult) == 0:
                answeredListResult = 0
            if len(unAnsweredListResult) == 0:
                unAnsweredListResult = 0

            return render_template('network_scanner_result.html', answeredListResult = answeredListResult, unAnsweredListResult = unAnsweredListResult)

        except Exception as e:
            return "Error : " + str(e)

    else:
        return 'For post requests only.'


if __name__ == '__main__':
    app.run(debug=True, port=5000)
