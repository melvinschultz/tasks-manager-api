<?php

/**
 * Gérer la connexion à la base
 *
 */
class DbConnect {

    private $conn;

    function __construct() {        
    }

    /**
     * établissement de la connexion
     * @return gestionnaire de connexion de base de données
     */
    function connect() {
        include_once dirname(__FILE__) . '/Config.php';

        // Connexion à la base de données mysql
        $this->conn = new mysqli(DB_HOST, DB_USERNAME, DB_PASSWORD, DB_NAME);

        // Vérifiez les erreurs de connexion àla base de données
        if (mysqli_connect_errno()) {
            echo "Impossible de se connecter à MySQL: " . mysqli_connect_error();
        }

        //retourner la ressource de connexion
        return $this->conn;
    }

}

