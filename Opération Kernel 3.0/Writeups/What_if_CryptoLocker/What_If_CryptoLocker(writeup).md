# Writeup :  What_If_CryptoLocker (reverse)
###### by Ak3la 
### CTF : Operation Kernel (2022) / Challenge reverse, 200 pts


L'objectif de ce challenge est de retrouver le flag au format : HACK{Utilisateur_Password}
Dans l'imaginaire du CTF, des pirates ont envoyées des documents sur un server pour les chiffer et il nous faut retrouver les identifiants. 
## Test du programme donné
Le fichier binaire du programme permettant de se connecter à ce server nous est donné.
Une fois telechargé, on l'execute pour voir ce qu'on peut en tirer :

    $ chmod +x crypto
    $ ./crypto
Nous obtenons :
  ```consol
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current`
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0curl: (6) Could not resolve host: qJqaL2L6Yl9jpTWmp3WlYaO1oay5pzS0pv5vL3Wyozq2LzRgrUWyLKW5YaAyY3Nl
Enter the key to encrypt files
```
Et en testant une clef au hasard, par exemple `ThisIsAKeyTest` : 
  ```consol
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current`
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0curl: (6) Could not resolve host: qJqaL2L6Yl9jpTWmp3WlYaO1oay5pzS0pv5vL3Wyozq2LzRgrUWyLKW5YaAyY3Nl
Enter the key to encrypt files
ThisIsAKeyTest



python: can't open file '/home/kali/Downloads/pzSjMJkwMl5woN==': [Errno 2] No such file or directory
python: can't open file '/home/kali/Downloads/pzSjMJkwMl5woN==': [Errno 2] No such file or directory
python: can't open file '/home/kali/Downloads/pzSjMJkwMl5woN==': [Errno 2] No such file or directory
python: can't open file '/home/kali/Downloads/pzSjMJkwMl5woN==': [Errno 2] No such file or directory
python: can't open file '/home/kali/Downloads/pzSjMJkwMl5woN==': [Errno 2] No such file or directory
```
La boucle infinie renvoyant l'erreur impose de kill l’exécution avec Ctrl+C. On conclue donc qu’exécuter le programme ne nous rapproche pas des identifiants cherchés, on passe donc au reverse !
## Reverse du programme
Pour passer du binaire à quelque chose de plus lisible, j'utilise Ghidra.

    $ ghidra
Une fois le projet initialisé avec le fichier "crypto", on analyse !
Personnellement, je souhaite toujours commencer l'étude du programme à reverse en affichant le binaire décompilé en pseudo C, les fonctions et les chaines de caractères présentes dans le fichier.

Observons la version décompilé du main (attention les yeux)
```c
undefined8 main(void)
{
	char *pcVar1;
  basic_string local_118 [32];
  basic_string<char,std::char_traits<char>,std::allocator<char>> local_f8 [32];
  basic_string<char,std::char_traits<char>,std::allocator<char>> local_d8 [46];
  allocator local_aa;
  allocator local_a9;
  basic_string local_a8 [32];
  basic_string<char,std::char_traits<char>,std::allocator<char>> local_88 [32];
  basic_string local_68 [32];
  basic_string<char,std::char_traits<char>,std::allocator<char>> local_48 [43];
  allocator local_1d;
  int local_1c;
  
  std::allocator<char>::allocator();
                    /* try { // try from 004042f2 to 004042f6 has its CatchHandler @ 004044aa */
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::
  basic_string<std::allocator<char>>
            (local_d8,"qJqaL2L6Yl9jpTWmp3WlYaO1oay5pzS0pv5vL3Wyozq2LzRgrUWyLKW5YaAyY3Nl",&local_aa);
  std::allocator<char>::~allocator((allocator<char> *)&local_aa);
  std::allocator<char>::allocator();
                    /* try { // try from 0040432b to 0040432f has its CatchHandler @ 004044c7 */
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::
  basic_string<std::allocator<char>>(local_f8,"pzSjMJkwMl5woN==",&local_a9);
  std::allocator<char>::~allocator((allocator<char> *)&local_a9);
                    /* try { // try from 00404349 to 00404374 has its CatchHandler @ 00404542 */
  getData((basic_string *)local_d8);
  getData((basic_string *)local_f8);
  std::operator+((char *)local_88,(basic_string *)"curl -O ");
                    /* try { // try from 0040438b to 0040438f has its CatchHandler @ 004044ef */
  std::operator+(local_a8,(char *)local_88);
                    /* try { // try from 004043ab to 004043af has its CatchHandler @ 004044db */
  std::operator+(local_118,local_a8);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)local_a8);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            (local_88);
  pcVar1 = (char *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::
                   c_str();
                    /* try { // try from 004043dd to 004043f7 has its CatchHandler @ 0040452e */
  system(pcVar1);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string
            (local_68);
  std::allocator<char>::allocator();
                    /* try { // try from 00404414 to 00404418 has its CatchHandler @ 00404511 */
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::
  basic_string<std::allocator<char>>(local_48,"/",&local_1d);
                    /* try { // try from 0040442e to 00404432 has its CatchHandler @ 00404500 */
  crypto((basic_string)0xb8,(basic_string *)local_d8,(basic_string)0x98);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            (local_48);
  std::allocator<char>::~allocator((allocator<char> *)&local_1d);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)local_68);
  pcVar1 = (char *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::
                   c_str();
  local_1c = remove(pcVar1);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)local_118);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            (local_f8);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            (local_d8);
  return 0;
}
```
On voit que 2 chaines de caractères sont créées (variables `local_d8` et `local_f8`) puis que ces variables sont placées en argument de la fonction  `getData()`
```c
  getData((basic_string *)local_d8);
  getData((basic_string *)local_f8);
```
Observons donc cette fonction décompilée : 
```c
 /*getData(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>&) */

void getData(basic_string *param_1)

{
  basic_string local_28 [32];
  
  rot(param_1,0xd);
  base64_decode(local_28);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
            ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)local_28);
  rot(param_1,0xd);
  return;
}
```
On voit qu'il s'agit d'un algorithme de déchiffrement. On prend une chaine de caractère, on exécute un ROT13 (0xd = 13), on déchiffre le résultat en base64, puis on réexécute un ROT13.

L'outil que j'utilise pour ce genre de chiffrement / déchiffrement successif est [CyberChef](https://gchq.github.io/CyberChef/).
On place les étapes de l'algorithme dans le bon sens, et de l'input 
`qJqaL2L6Yl9jpTWmp3WlYaO1oay5pzS0pv5vL3Wyozq2LzRgrUWyLKW5YaAyY3Nl`
On obtient :
`https://ccoffee.challenge.operation-kernel.fr/c2`

Ce lien est visible, l'algorithme  fonctionne, on teste avec les autres chaines de caractères du fichier binaire trouvées avec Ghidra :
`pzSjMJkwMl5woN==`
`nTMlMG1iLzpzL25zMzcvMKR9GaSkEJWaIzMTM3M5rHSvM1WuLzu0qD==` 

Input : `pzSjMJkwMl5woN==` 
Output : `encrypt.py` 

Input : `nTMlMG1iLzpzL25zMzcvMKR9GaSkEJWaIzMTM3M5rHSvM1WuLzu0qD==` 
Output : `user=bot&password=AddRotIsStillNotEnough` 

Nous avons donc le contenu d'une requête avec le Username et le Password donc nous avons besoin pour flag. Le flag est donc **HACK{bot_AddRotIsStillNotEnough}**



