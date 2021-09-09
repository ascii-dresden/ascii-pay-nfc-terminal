
type RequestAccountAccessToken = {
    type: 'RequestAccountAccessToken',
    payload: {}
}
type RequestReboot = {
    type: 'RequestReboot',
    payload: {}
}
type RegisterNfcCard = {
    type: 'RegisterNfcCard',
    payload: {
        account_id: string
    }
}
export type WebSocketRequest = RequestAccountAccessToken | RequestReboot | RegisterNfcCard

type FoundUnknownBarcode = {
    type: 'FoundUnknownBarcode',
    payload: {
        code: string
    }
}
type FoundUnknownNfcCard = {
    type: 'FoundUnknownNfcCard',
    payload: {
        id: string,
        name: string
    }
}
type FoundProductId = {
    type: 'FoundProductId',
    payload: {
        product_id: string
    }
}
type FoundAccountAccessToken = {
    type: 'FoundAccountAccessToken',
    payload: {
        access_token: string
    }
}
type NfcCardRemoved = {
    type: 'NfcCardRemoved',
    payload: {}
}
export type WebSocketResponse = FoundUnknownBarcode | FoundUnknownNfcCard | FoundProductId | FoundAccountAccessToken | NfcCardRemoved

export type WebSocketMessageHandler = (message: WebSocketResponse) => void

export class AsciiPayAuthenticationClient {
    url: string
    socket: WebSocket
    handlerList: WebSocketMessageHandler[]

    constructor(url: string) {
        this.url = url
        this.createWebSocket()
        this.handlerList = []
    }

    private createWebSocket() {
        let self = this
        this.socket = new WebSocket('ws://localhost:8080')

        this.socket.addEventListener('close', function (event) {
            setTimeout(() => {
                self.createWebSocket()
            }, 1000)
        })

        this.socket.addEventListener('message', function(event) {
            let message: WebSocketResponse = JSON.parse(event.data)

            for (const handler of self.handlerList) {
                handler(message)
            }
        })
    }

    addEventHandler(handler: WebSocketMessageHandler) {
        this.handlerList.push(handler)
    }

    removeEventHandler(handler: WebSocketMessageHandler) {
        const index = this.handlerList.indexOf(handler)
        if (index >= 0) {
            this.handlerList.splice(index, 1)
        }
    }

    requestAccountAccessToken() {
        const message: RequestAccountAccessToken = {
            type: 'RequestAccountAccessToken',
            payload: {}
        }

        this.socket.send(JSON.stringify(message))
    }

    requestReboot() {
        const message: RequestReboot = {
            type: 'RequestReboot',
            payload: {}
        }

        this.socket.send(JSON.stringify(message))
    }

    registerNfcCard(account_id: string) {
        const message: RegisterNfcCard = {
            type: 'RegisterNfcCard',
            payload: {
                account_id: account_id
            }
        }

        this.socket.send(JSON.stringify(message))
    }
}
