<?php

namespace App\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;

class HeaderController extends AbstractController
{
    public function header(SessionInterface $session): Response
    {
        // !!!!! Sommes des items dans le panier !!!!!
        // On récupère le panier de la session actuelle
        // $panier = $session->get("panier", []);  // Soit la session vaut "panier", soit un tableau vide

        // $quantiteTotale = 0;

        // foreach ($panier as $quantite)
        // {
        //     $quantiteTotale += $quantite;
        // }
        // dd($quantiteTotale);

        return $this->render('partials/_header.html.twig', [
            // 'quantiteTotale' => $quantiteTotale,
        ]);
    }
}
