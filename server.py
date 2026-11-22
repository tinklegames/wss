"""Portable binary WebSocket/TCP relay for the audited MSM authentication hosts."""
import asyncio,hmac,logging,os,socket
from pathlib import Path
from urllib.parse import parse_qs,urlsplit
from aiohttp import WSMsgType, web

HOSTS=frozenset({'dlc2.bbbgame.net', 'msm-mobile-prod-v2.bbbgame.net', 'newsflash-api.bbbgame.net', 'ad-assets.bbbgame.net', 'auth.bbbgame.net','msm-auth.bbbgame.net','6df86d1d2fb0.us-east-1.sdk.awswaf.com'})
MAX_BYTES=64*1024*1024

class Relay:
 def __init__(self,token,origins,connector=asyncio.open_connection):
  if len(token)<32:raise ValueError('RELAY_TOKEN must contain at least 32 characters')
  if not origins:raise ValueError('At least one allowed origin is required')
  self.token=token;self.origins=frozenset(origins);self.connector=connector;self.active=0
 def authorize(self,request):
  url=urlsplit(request.raw_path);q=parse_qs(url.query)
  if url.path!='/game-socket':return 404,'Not found',None
  if request.headers.get('Origin') not in self.origins:return 403,'Origin denied',None
  if not hmac.compare_digest(q.get('token',[''])[0],self.token):return 401,'Invalid relay token',None
  host=q.get('host',[''])[0];port=q.get('port',[''])[0]
  if host not in HOSTS or port!='443':return 403,'Endpoint denied',None
  if 'binary' not in [s.strip() for s in request.headers.get('Sec-WebSocket-Protocol','').split(',')]:return 400,'Binary subprotocol required',None
  return 200,'OK',(host,443)
 async def health(self,request):
  return web.json_response({'service':'APKWASM MSM WSS proxy','ready':True})

 async def handler(self,request):
  status,message,target=self.authorize(request)
  if status!=200:return web.Response(status=status,text=message)
  if self.active>=8:return web.Response(status=503,text='Connection limit')
  connection=web.WebSocketResponse(protocols=('binary',),compress=False,
   max_msg_size=1024*1024,heartbeat=20)
  if not connection.can_prepare(request).ok:
   return web.Response(status=400,text='WebSocket upgrade required')
  self.active+=1;writer=None;tasks=[];sent=received=0
  try:
   await connection.prepare(request)
   reader,writer=await asyncio.wait_for(self.connector(*target),15)
   sock=writer.get_extra_info('socket')
   if sock:sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
   async def outbound():
    nonlocal sent
    async for message in connection:
     if message.type!=WSMsgType.BINARY:
      await connection.close(code=1003,message=b'Binary data required');return
     data=message.data
     sent+=len(data)
     if sent>MAX_BYTES:await connection.close(code=1009,message=b'Transfer limit');return
     writer.write(data);await writer.drain()
   async def inbound():
    nonlocal received
    while data:=await reader.read(65536):
     received+=len(data)
     if received>MAX_BYTES:await connection.close(code=1009,message=b'Transfer limit');return
     await connection.send_bytes(data)
   tasks=[asyncio.create_task(outbound()),asyncio.create_task(inbound())]
   await asyncio.wait(tasks,timeout=900,return_when=asyncio.FIRST_COMPLETED)
  except (OSError,TimeoutError):pass
  finally:
   for task in tasks:
    if not task.done():task.cancel()
   await asyncio.gather(*tasks,return_exceptions=True)
   if writer:
    writer.close()
    try:await writer.wait_closed()
    except OSError:pass
   self.active-=1
   await connection.close()
   # Never log query strings, tokens, or game payloads.
   logging.info('Relay closed: sent=%d received=%d',sent,received)
  return connection

 def application(self):
  app=web.Application()
  app.router.add_get('/',self.health)
  app.router.add_get('/health',self.health)
  app.router.add_get('/game-socket',self.handler,allow_head=False)
  return app

def main():
 token_file=os.environ.get('RELAY_TOKEN_FILE')
 token=Path(token_file).read_text().strip() if token_file else os.environ.get('RELAY_TOKEN','')
 relay=Relay(token,[s.strip() for s in os.environ.get('ALLOWED_ORIGINS','http://127.0.0.1:8877,http://localhost:8877').split(',') if s.strip()])
 port=int(os.environ.get('PORT','10000'))
 logging.basicConfig(level=logging.INFO,format='%(levelname)s %(message)s')
 # Access logs would include the client token from the WebSocket URL.
 web.run_app(relay.application(),host='0.0.0.0',port=port,access_log=None)

if __name__=='__main__':main()
