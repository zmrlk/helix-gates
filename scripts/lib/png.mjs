// PNG codec for browser screenshots: 8-bit non-interlaced gray/RGB/palette/RGBA.
// Unsupported encodings fail closed. No optional npm package is required.
import zlib from 'node:zlib';
const signature = Buffer.from('89504e470d0a1a0a', 'hex');
function crc(data) {
  let c = 0xffffffff;
  for (const byte of data) { c ^= byte; for (let i=0;i<8;i++) c = (c >>> 1) ^ ((c & 1) ? 0xedb88320 : 0); }
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const body = Buffer.concat([Buffer.from(type), data]), out = Buffer.alloc(data.length+12);
  out.writeUInt32BE(data.length); body.copy(out,4); out.writeUInt32BE(crc(body),out.length-4); return out;
}
function dimensions(w,h) { if (!w || !h || w*h>40000000) throw new Error('PNG exceeds 40 million pixels'); }
function read(buffer) {
  if (!buffer.subarray(0,8).equals(signature)) throw new Error('Invalid PNG signature');
  let width,height,type,channels,palette,alpha,ended=false; const parts=[];
  for (let p=8;p<buffer.length;) {
    if (p+12>buffer.length) throw new Error('Truncated PNG');
    const length=buffer.readUInt32BE(p), end=p+12+length;
    if (end>buffer.length) throw new Error('Truncated PNG chunk');
    const name=buffer.toString('ascii',p+4,p+8), data=buffer.subarray(p+8,end-4);
    if (crc(buffer.subarray(p+4,end-4))!==buffer.readUInt32BE(end-4)) throw new Error('PNG CRC mismatch');
    if (p===8 && name!=='IHDR') throw new Error('PNG missing IHDR');
    if (name==='IHDR') {
      if (width || length!==13) throw new Error('Invalid PNG header');
      width=data.readUInt32BE(0);height=data.readUInt32BE(4);dimensions(width,height);type=data[9];
      channels=({0:1,2:3,3:1,4:2,6:4})[type];
      if (data[8]!==8 || !channels || data[10] || data[11] || data[12]) throw new Error('Unsupported PNG encoding');
    } else if (name==='PLTE') palette=data;
    else if (name==='tRNS') alpha=data;
    else if (name==='IDAT') parts.push(data);
    else if (name==='IEND') { ended=true; break; }
    else if (name[0]===name[0].toUpperCase()) throw new Error('Unsupported critical PNG chunk');
    p=end;
  }
  if (!ended || !parts.length) throw new Error('Incomplete PNG');
  const stride=width*channels, raw=zlib.inflateSync(Buffer.concat(parts),{maxOutputLength:(stride+1)*height});
  if (raw.length!==(stride+1)*height) throw new Error('Invalid PNG scanlines');
  const decoded=Buffer.alloc(stride*height), data=Buffer.alloc(width*height*4);
  const paeth=(a,b,c)=>{const p=a+b-c, x=Math.abs(p-a),y=Math.abs(p-b),z=Math.abs(p-c);return x<=y&&x<=z?a:y<=z?b:c;};
  for(let y=0;y<height;y++) {
    const filter=raw[y*(stride+1)]; if(filter>4) throw new Error('Invalid PNG filter');
    for(let x=0;x<stride;x++) {
      const i=y*stride+x,a=x>=channels?decoded[i-channels]:0,b=y?decoded[i-stride]:0,c=y&&x>=channels?decoded[i-stride-channels]:0;
      decoded[i]=(raw[y*(stride+1)+1+x]+[0,a,b,Math.floor((a+b)/2),paeth(a,b,c)][filter])&255;
    }
  }
  for(let i=0;i<width*height;i++) {
    const s=i*channels,d=i*4;
    if(type===3) {
      const n=decoded[s]; if(!palette || n*3+2>=palette.length) throw new Error('Invalid PNG palette');
      palette.copy(data,d,n*3,n*3+3);data[d+3]=alpha?.[n]??255;
    } else if(type===0 || type===4) {
      data[d]=data[d+1]=data[d+2]=decoded[s];data[d+3]=type===4?decoded[s+1]:alpha&&decoded[s]===alpha.readUInt16BE(0)?0:255;
    } else {
      decoded.copy(data,d,s,s+3);data[d+3]=type===6?decoded[s+3]:alpha&&decoded[s]===alpha.readUInt16BE(0)&&decoded[s+1]===alpha.readUInt16BE(2)&&decoded[s+2]===alpha.readUInt16BE(4)?0:255;
    }
  }
  return {width,height,data};
}
function write({width,height,data}) {
  dimensions(width,height);if(data.length!==width*height*4) throw new Error('Invalid RGBA data');
  const header=Buffer.alloc(13);header.writeUInt32BE(width);header.writeUInt32BE(height,4);header[8]=8;header[9]=6;
  const raw=Buffer.alloc((width*4+1)*height);
  for(let y=0;y<height;y++) data.copy(raw,y*(width*4+1)+1,y*width*4,(y+1)*width*4);
  return Buffer.concat([signature,chunk('IHDR',header),chunk('IDAT',zlib.deflateSync(raw)),chunk('IEND',Buffer.alloc(0))]);
}
export class PNG {
  constructor({width,height}) {dimensions(width,height);this.width=width;this.height=height;this.data=Buffer.alloc(width*height*4);}
  static sync={read,write};
}
