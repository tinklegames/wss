"""Portable binary WebSocket/TCP relay for the audited MSM authentication hosts."""
import asyncio,hmac,json,logging,os,socket
from http import HTTPStatus
from pathlib import Path
from urllib.parse import parse_qs,urlsplit
from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed

HOSTS=frozenset({'auth.bbbgame.net','msm-auth.bbbgame.net','6df86d1d2fb0.us-east-1.sdk.awswaf.com'})
MAX_BYTES=64*1024*1024

class Relay:
 def __init__(self,token,origins,connector=asyncio.open_connection):
  if len(token)<32:raise ValueError('RELAY_TOKEN must contain at least 32 characters')
  if not origins:raise ValueError('At least one allowed origin is required')
  self.token=token;self.origins=frozenset(origins);self.connector=connector;self.active=0
 def authorize(self,request):
  url=urlsplit(request.path);q=parse_qs(url.query)
  if url.path!='/game-socket':return 404,'Not found',None
  if request.headers.get('Origin') not in self.origins:return 403,'Origin denied',None
  if not hmac.compare_digest(q.get('token',[''])[0],self.token):return 401,'Invalid relay token',None
  host=q.get('host',[''])[0];port=q.get('port',[''])[0]
  if host not in HOSTS or port!='443':return 403,'Endpoint denied',None
  if 'binary' not in [s.strip() for s in request.headers.get('Sec-WebSocket-Protocol','').split(',')]:return 400,'Binary subprotocol required',None
  return 200,'OK',(host,443)
 async def process_request(self,connection,request):
  # Health checks never expose the token or start an upstream connection.
  if urlsplit(request.path).path in ('/','/health'):
   response=connection.respond(HTTPStatus.OK,json.dumps({'service':'APKWASM MSM WSS proxy','ready':True}))
   response.headers['Content-Type']='application/json';return response
  status,message,_=self.authorize(request)
  if status!=200:return connection.respond(HTTPStatus(status),message)
  if self.active>=8:return connection.respond(HTTPStatus.SERVICE_UNAVAILABLE,'Connection limit')
 async def handler(self,connection):
  status,_,target=self.authorize(connection.request)
  if status!=200 or self.active>=8:await connection.close(1008,'Connection denied');return
  self.active+=1;writer=None;tasks=[];sent=received=0
  try:
   reader,writer=await asyncio.wait_for(self.connector(*target),15)
   sock=writer.get_extra_info('socket')
   if sock:sock.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
   async def outbound():
    nonlocal sent
    async for data in connection:
     if not isinstance(data,bytes):await connection.close(1003,'Binary data required');return
     sent+=len(data)
     if sent>MAX_BYTES:await connection.close(1009,'Transfer limit');return
     writer.write(data);await writer.drain()
   async def inbound():
    nonlocal received
    while data:=await reader.read(65536):
     received+=len(data)
     if received>MAX_BYTES:await connection.close(1009,'Transfer limit');return
     await connection.send(data)
   tasks=[asyncio.create_task(outbound()),asyncio.create_task(inbound())]
   await asyncio.wait(tasks,timeout=900,return_when=asyncio.FIRST_COMPLETED)
  except (OSError,TimeoutError,ConnectionClosed):pass
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
 def server(self,host='0.0.0.0',port=10000,**kwargs):
  return serve(self.handler,host,port,process_request=self.process_request,
   origins=list(self.origins),subprotocols=['binary'],compression=None,
   max_size=1024*1024,max_queue=4,write_limit=65536,ping_interval=20,ping_timeout=20,**kwargs)

async def main():
 token_file=os.environ.get('RELAY_TOKEN_FILE')
 token=Path(token_file).read_text().strip() if token_file else os.environ.get('RELAY_TOKEN','')
 relay=Relay(token,[s.strip() for s in os.environ.get('ALLOWED_ORIGINS','http://127.0.0.1:8877,http://localhost:8877').split(',') if s.strip()])
 port=int(os.environ.get('PORT','10000'))
 logging.basicConfig(level=logging.INFO,format='%(levelname)s %(message)s')
 async with relay.server(port=port):
  logging.info('MSM relay listening on port %d',port)
  await asyncio.Future()
if __name__=='__main__':asyncio.run(main())
