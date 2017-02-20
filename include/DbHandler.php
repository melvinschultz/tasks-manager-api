<?php

/**
 * Classe pour gérer toutes les opérations de db
 * Cette classe aura les méthodes CRUD pour les tables de base de données
 *

 */
class DbHandler {

    private $conn;

    function __construct() {
        require_once dirname(__FILE__) . '/DbConnect.php';
        //Ouverture connexion db
        $db = new DbConnect();
        $this->conn = $db->connect();
    }

    /* ------------- méthodes de la table `users` ------------------ */

    /**
     * Creation nouvel utilisateur
     * @param String $name nom complet de l'utilisateur
     * @param String $email email de connexion
     * @param String $password mot de passe de connexion
     */
    public function createUser($name, $email, $password) {
        require_once 'PassHash.php';


        // Vérifiez d'abord si l'utilisateur existe déjà dans db
        if (!$this->isUserExists($email)) {
            //Générer un hash de mot de passe
            $password_hash = PassHash::hash($password);

            // Générer API key
            $api_key = $this->generateApiKey();

            // requete d'insertion
            $stmt = $this->conn->prepare("INSERT INTO users(name, email, password_hash, api_key, status) values(?, ?, ?, ?, 1)");
            $stmt->bind_param("ssss", $name, $email, $password_hash, $api_key);

            $result = $stmt->execute();

            $stmt->close();

            //Vérifiez pour une insertion réussie
            if ($result) {
                // Utilisateur inséré avec succès
                return USER_CREATED_SUCCESSFULLY;
            } else {
                //Échec de la création de l'utilisateur
                return USER_CREATE_FAILED;
            }
        } else {
            //Utilisateur avec la même email existait déjà dans la db
            return USER_ALREADY_EXISTED;
        }


    }

    /**
     * Vérification de connexion de l'utilisateur
     * @param String $email
     * @param String $password
     * @return boolean Le statut de connexion utilisateur réussite / échec
     */
    public function checkLogin($email, $password) {
        // Obtention de l'utilisateur par email
        $stmt = $this->conn->prepare("SELECT password_hash FROM users WHERE email = ?");

        $stmt->bind_param("s", $email);

        $stmt->execute();

        $stmt->bind_result($password_hash);

        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            // Utilisateur trouvé avec l'e-mail
            // Maintenant, vérifier le mot de passe

            $stmt->fetch();

            $stmt->close();

            if (PassHash::check_password($password_hash, $password)) {
                // Mot de passe utilisateur est correcte
                return TRUE;
            } else {
                // mot de passe utilisateur est incorrect
                return FALSE;
            }
        } else {
            $stmt->close();

            // utilisateur n'existe pas avec l'e-mail
            return FALSE;
        }
    }

    /**
     * Vérification de l'utilisateur en double par adresse e-mail
     * @param String $email email à vérifier dans la db
     * @return boolean
     */
    private function isUserExists($email) {
        $stmt = $this->conn->prepare("SELECT id from users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }

    /**
     *Obtention de l'utilisateur par email
     * @param String $email
     */
    public function getUserByEmail($email) {
        $stmt = $this->conn->prepare("SELECT name, email, api_key, status, created_at FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        if ($stmt->execute()) {
            $stmt->bind_result($name, $email, $api_key, $status, $created_at);
            $stmt->fetch();
            $user = array();
            $user["name"] = $name;
            $user["email"] = $email;
            $user["api_key"] = $api_key;
            $user["status"] = $status;
            $user["created_at"] = $created_at;
            $stmt->close();
            return $user;
        } else {
            return NULL;
        }
    }

    /**
     * Obtention de la clé API de l'utilisateur
     * @param String $user_id clé primaire de l'utilisateur
     */
    public function getApiKeyById($user_id) {
        $stmt = $this->conn->prepare("SELECT api_key FROM users WHERE id = ?");
        $stmt->bind_param("i", $user_id);
        if ($stmt->execute()) {
            $stmt->bind_result($api_key);
            $stmt->close();
            return $api_key;
        } else {
            return NULL;
        }
    }

    /**
     * Obtention de l'identifiant de l'utilisateur par clé API
     * @param String $api_key
     */
    public function getUserId($api_key) {
        $stmt = $this->conn->prepare("SELECT id FROM users WHERE api_key = ?");
        $stmt->bind_param("s", $api_key);
        if ($stmt->execute()) {
            $stmt->bind_result($user_id);
            $stmt->fetch();

            $stmt->close();
            return $user_id;
        } else {
            return NULL;
        }
    }

    /**
     * Validation de la clé API de l'utilisateur
     * Si la clé API est là dans db, elle est une clé valide
     * @param String $api_key
     * @return boolean
     */
    public function isValidApiKey($api_key) {
        $stmt = $this->conn->prepare("SELECT id from users WHERE api_key = ?");
        $stmt->bind_param("s", $api_key);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }

    /**
     * Génération aléatoire unique MD5 String pour utilisateur clé Api
     */
    private function generateApiKey() {
        return md5(uniqid(rand(), true));
    }

    /* ------------- méthodes table`tasks` ------------------ */

    /**
     * Creation nouvelle tache
     * @param String $user_id id de l'utilisateur à qui la tâche appartient
     * @param String $task texte de la tache
     */
    public function createTask($user_id, $task) {
        $stmt = $this->conn->prepare("INSERT INTO tasks(task) VALUES(?)");
        $stmt->bind_param("s", $task);
        $result = $stmt->execute();
        $stmt->close();

        if ($result) {
            // ligne de tâche créé
            // maintenant assigner la tâche à l'utilisateur
            $new_task_id = $this->conn->insert_id;
            $res = $this->createUserTask($user_id, $new_task_id);
            if ($res) {
                // tâche créée avec succès
                return $new_task_id;
            } else {
                //tâche n'a pas pu être créé
                return NULL;
            }
        } else {
            //tâche n'a pas pu être créé
            return NULL;
        }
    }

    /**
     * Obtention d'une seule tâche
     * @param String $task_id id de la tâche
     */
    public function getTask($task_id, $user_id) {
        $stmt = $this->conn->prepare("SELECT t.id, t.task, t.status, t.created_at from tasks t, user_tasks ut WHERE t.id = ? AND ut.task_id = t.id AND ut.user_id = ?");
        $stmt->bind_param("ii", $task_id, $user_id);
        if ($stmt->execute()) {
            $res = array();
            $stmt->bind_result($id, $task, $status, $created_at);
            $stmt->fetch();
            $res["id"] = $id;
            $res["task"] = $task;
            $res["status"] = $status;
            $res["created_at"] = $created_at;
            $stmt->close();
            return $res;
        } else {
            return NULL;
        }
    }

    /**
     *Obtention de  tous les  tâches de l'utilisateur
     * @param String $user_id id de l'utilisateur
     */
    public function getAllUserTasks($user_id) {
        $stmt = $this->conn->prepare("SELECT t.* FROM tasks t, user_tasks ut WHERE t.id = ut.task_id AND ut.user_id = ?");
        $stmt->bind_param("i", $user_id);
        $stmt->execute();
        $tasks = $stmt->get_result();
        $stmt->close();
        return $tasks;
    }

    /**
     * Mise à jour de la tâche
     * @param String $task_id id de la tâche
     * @param String $task Le texte de la tâche
     * @param String $status le statut de la tâche
     */
    public function updateTask($user_id, $task_id, $task) {
        $stmt = $this->conn->prepare("UPDATE tasks t, user_tasks ut set t.task = ? WHERE t.id = ? AND t.id = ut.task_id AND ut.user_id = ?");
        $stmt->bind_param("sii", $task, $task_id, $user_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }

    /**
     * Suppression d'une tâche
     * @param String $task_id id de la tâche à supprimer
     */
    public function deleteTask($user_id, $task_id) {
        $stmt = $this->conn->prepare("DELETE t FROM tasks t, user_tasks ut WHERE t.id = ? AND ut.task_id = t.id AND ut.user_id = ?");
        $stmt->bind_param("ii", $task_id, $user_id);
        $stmt->execute();
        $num_affected_rows = $stmt->affected_rows;
        $stmt->close();
        return $num_affected_rows > 0;
    }

    /* ------------- méthode de la table`user_tasks` ------------------ */

    /**
     * Fonction d'assigner une tâche à l'utilisateur
     * @param String $user_id id de l'utilisateur
     * @param String $task_id id de la tâche
     */
    public function createUserTask($user_id, $task_id) {
        $stmt = $this->conn->prepare("INSERT INTO user_tasks(user_id, task_id) values(?, ?)");
        $stmt->bind_param("ii", $user_id, $task_id);
        $result = $stmt->execute();

        if (false === $result) {
            die('execute() failed: ' . htmlspecialchars($stmt->error));
        }
        $stmt->close();
        return $result;
    }

}

