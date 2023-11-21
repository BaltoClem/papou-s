<?php

namespace App\Controller;

use App\Entity\User;
use App\Entity\PasswordReset;
use App\Form\ResetPasswordType;
use App\Service\TokenGenerator;
use Symfony\Component\Mime\Email;
use App\Form\EmailForResetPasswordType;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Mailer\Exception\TransportExceptionInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;


class ResetPasswordController extends AbstractController
{
    private $mailer;
    private $passwordHasher;

    public function __construct(MailerInterface $mailer, UserPasswordHasherInterface $passwordHasher)
    {
        $this->mailer = $mailer;
        $this->passwordHasher = $passwordHasher;
    }

    #[Route('/reset-password/request', name: 'reset_password_request')]
    /**
     * This controller allows us to make a password reset request
     *
     * @param Request $request
     * @param EntityManagerInterface $entityManager
     * @param TokenGenerator $tokenGenerator
     * @return Response
     */
    public function request(Request $request, EntityManagerInterface $entityManager, TokenGenerator $tokenGenerator): Response
    {
        $form = $this->createForm(EmailForResetPasswordType::class);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $email = $form->get('email')->getData();
            $user = $entityManager->getRepository(User::class)->findOneBy(['email' => $email]);

            if ($user) {
                // Utilisateur trouvé, générer un jeton de réinitialisation
                $token = $tokenGenerator->generateToken();

                // Enregistrer le token en base de données
                $passwordReset = new PasswordReset();
                $passwordReset->setEmail($email);
                $passwordReset->setToken($token);
                $passwordReset->setCreatedAt(new \DateTime());

                $entityManager->persist($passwordReset);
                $entityManager->flush();

                // Envoyer un email avec le lien de réinitialisation
                try {
                    $this->sendResetPasswordEmail($user, $token);
                    // !!!!! MESSAGE FLASH !!!!!
                    $this->addFlash    // Nécessite un block "for message" dans le fichier .html.twig pour fonctionner
                    (
                        'success',  // Nom de l'alerte 
                        ['info' => 'Demande de réinitialisation du mot de passe', 'bonus' => "Un email de réinitialisation a été envoyé à votre adresse."]  // Message(s)
                    );
                } catch (TransportExceptionInterface $e) {
                    // !!!!! MESSAGE FLASH !!!!!
                    $this->addFlash    // Nécessite un block "for message" dans le fichier .html.twig pour fonctionner
                    (
                        'danger',  // Nom de l'alerte 
                        ['info' => 'Erreur', 'bonus' => "Un problème est survenu lors de l'envoi de l'email."]  // Message(s)
                    );
                }
            } else {
                // !!!!! MESSAGE FLASH !!!!!
                $this->addFlash    // Nécessite un block "for message" dans le fichier .html.twig pour fonctionner
                (
                    'danger',  // Nom de l'alerte 
                    ['info' => 'Erreur', 'bonus' => "Aucun utilisateur trouvé avec cette adresse email."]  // Message(s)
                );
            }
            return $this->redirectToRoute('security.login');
        }

        return $this->render('pages/security/resetPassword/emailForResetPassword.html.twig', [
            'form' => $form->createView(),
        ]);

    }


    private function sendResetPasswordEmail(User $user, string $token): void
    {
        $url = $this->generateUrl('reset_password_confirm', ['token' => $token], UrlGeneratorInterface::ABSOLUTE_URL);

        $email = (new Email())
            ->from('noreply@papou.com')
            ->to($user->getEmail())
            ->subject('Réinitialisation de mot de passe')
            ->html($this->renderView('emails/reset_password.html.twig', [
                'user' => $user,
                'token' => $token,
                'url' => $url,
            ]));

        $this->mailer->send($email);
    }


    #[Route('/reset-password/confirm/{token}', name: 'reset_password_confirm')]
    /**
     * This controller allows us to make a password reset
     *
     * @param Request $request
     * @param EntityManagerInterface $entityManager
     * @param string $token
     * @return Response
     */
    public function confirm(Request $request, EntityManagerInterface $entityManager, string $token): Response
    {
        // Récupérer la demande de réinitialisation correspondant au token
        $passwordReset = $entityManager->getRepository(PasswordReset::class)->findOneBy(['token' => $token]);

        // Vérifier si la demande de réinitialisation existe et n'a pas expiré
        if (!$passwordReset || $passwordReset->isExpired()) {
            // !!!!! MESSAGE FLASH !!!!!
            $this->addFlash    // Nécessite un block "for message" dans le fichier .html.twig pour fonctionner
            (
                'danger',  // Nom de l'alerte 
                ['info' => 'Erreur', 'bonus' => "Le lien de réinitialisation de votre mot de passe à expiré. Veuillez effectuer une nouvelle demande de réinitialisation."]  // Message(s)
            );

            // Supprimer la demande de réinitialisation expirée
            if ($passwordReset) {
                $entityManager->remove($passwordReset);
                $entityManager->flush();
            }
            
            // Rediriger l'utilisateur ou prendre d'autres mesures nécessaires...
            return $this->redirectToRoute('security.login');
        }

        // Récupérer l'utilisateur associé à l'adresse email dans la demande de réinitialisation
        $user = $entityManager->getRepository(User::class)->findOneBy(['email' => $passwordReset->getEmail()]);

        // Créer le formulaire de réinitialisation du mot de passe
        $form = $this->createForm(ResetPasswordType::class, $user);
        $form->handleRequest($request);

        // Traiter le formulaire lorsqu'il est soumis
        if ($form->isSubmitted() && $form->isValid()) {

            // Encoder et définir le nouveau mot de passe de l'utilisateur
            $encodedPassword = $this->passwordHasher->hashPassword($user, $form->get('plainPassword')->getData());
            $user->setPassword($encodedPassword);

            // dd($user);

            // Supprimer la demande de réinitialisation pour éviter une utilisation multiple
            $entityManager->remove($passwordReset);
            $entityManager->flush();

            // !!!!! MESSAGE FLASH !!!!!
            $this->addFlash    // Nécessite un block "for message" dans le fichier .html.twig pour fonctionner
            (
                'success',  // Nom de l'alerte 
                ['info' => 'Réinitialisation du mot de passe', 'bonus' => "Votre mot de passe à été modifié avec succès"]  // Message(s)
            );

            // Rediriger l'utilisateur vers la page de connexion
            return $this->redirectToRoute('security.login');
        }

        // Afficher le formulaire de réinitialisation du mot de passe
        return $this->render('pages/security/resetPassword/resetPassword.html.twig', [
            'form' => $form->createView(),
        ]);
    }
}
