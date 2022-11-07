# scanWhois
Herramienta hecha en Python que recopila información en una fase de reconocimiento de un ataque

# Funcionamiento
- Al ejecutarlo te pide un domino, se lo introduces.
- El Script comprueba el registro Whois del dominio.
- Obtiene el DNS Record del dominio.
- Te muestra los datos del Whois y la lista de DNS de tipo NS y MX.
- Comprueba si existen filtraciones para correos con los dominios MX encontrados en Have I Been Pwned, si encuentra filtraciones te muestra la información.
- Realiza un PING al dominio para comprobar si está vivo.
- Realiza un Scan NMAP a los Top10 Ports TCP y te muestra el resultado.

# Requisitos
- Tener Python instalado
- Tener las bibliotecas requests, re, sys y subprocess instaladas
- Tu equipo debe poder realizar PINGs.
- Tener instalado NMAP.

# Disclaimers
Esto es una práctica universitaria, no una aplicación funcional, por lo que no es 100% util, ya que hace lo que se pide en la práctica. Además hace uso de una API que tiene un límite de llamadas mensuales (WhoisXMLAPI), por lo que este programa no está enfocado al uso funcional, sino para usarse como fuente de aprendizaje acad
