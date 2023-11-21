<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\RegistrationType;
use App\Service\TokenGenerator;
use Symfony\Component\Mime\Email;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Mailer\Exception\TransportExceptionInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

class SecurityController extends AbstractController
{
    #[Route('/login', name: 'security.login', methods:['GET', 'POST'])]
     /**
     * This controller allows us to login
     *
     * @param AuthenticationUtils $authenticationUtils
     * @return Response
     */
    public function login(AuthenticationUtils $authenticationUtils): Response  // AuthenticationUtils nécessaire pour last_username dans login.html.twig
    {
        // Récupérer l'erreur de la dernière tentative de connexion
        $error = $authenticationUtils->getLastAuthenticationError();

        // Récupérer le dernier nom d'utilisateur saisi par l'utilisateur
        $lastUsername = $authenticationUtils->getLastUsername();

        // Message personnalisé en cas d'erreur
        if ($error) {
            // !!!!! MESSAGE FLASH !!!!!
            $this->addFlash    // Nécessite un block "for message" dans le fichier .html.twig pour fonctionner
            (
                'danger',  // Nom de l'alerte 
                ['info' => 'Erreur', 'bonus' => "Adresse mail ou mot de passe invalide"]  // Message(s)
            );
        }

        return $this->render('pages/security/login.html.twig', [
            'last_username' => $lastUsername,
            'error' => $error,
        ]);
    }


    #[Route('/logout', name: 'security.logout', methods:['GET', 'POST'])]
    /**
     * This controller allows us to logout
     *
     * @return void
     */
    public function logout()
    {
        // Nothing to do here...
    }


}