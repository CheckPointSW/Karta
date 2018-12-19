File Map Logic
===========
The file map, and the logic that is implemented on top of it, is the key concept of **Karta**. While different implementations can use different scoring algorithms, and use different matching tactics, we believe that the file map can be used in other binary matching tools as well.

Having that in mind, we built our matching engine out of 2 main parts:
1. File Layer - describes the file map, and the ability to define a file in a given scope, mark functions inside as matched, etc.
2. Matching Engine - Basic matching engine that initializes the file map using anchors, including the logic needed in order to find those anchors.

As one can see, these 2 parts can be used by other matching tools, and so we've put them inside the ```src\core``` folder. The additional logic that **Karta** adds on top of these layers, such as file based matching tactics (searching for neighbours), or matching steps, is implemented in other classes that inherits from these basic class (and carry the same name).

We hope that other matching tools could integrate our file map logic, and hopefully will profit from it as well.