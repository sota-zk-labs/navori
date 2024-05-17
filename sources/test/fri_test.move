#[test_only]
module verifier_addr::fri_test {
    use std::vector;
    use verifier_addr::fri_statement;

    public fun get_proof_2(): vector<u256> {
        vector[
            389282056495343921793645528583513338986880224704383530277583690238776314129,
            504237632094591233105439563415863289176412405823917879582466742272347732040,
            757533840847594835849918528026483192301860340796280580018925625617990980290,
            1166001706683995178916123796765712284922499824910503533245628939961248114255,
            2278644470989600112191233252885797839616635819878345516394218916632907949421,
            3435553746256854945944281334925765399235047111969118929027844835093565412906,
            2527708622951429906478078520003915642212892374308027307050756926891603149882,
            445851849999480279746563207044675219598467409617502317254570800482439936755,
            2590125043726527869280516438950250891904369162284132713013969442809941608293,
            2259494019517901025720566913182311181805961035302151189448239935001123896155,
            821877123550177196789801583721931082660247069163350609058692695028151709412,
            3058224711449689935189736902030801816297688514615402309587936145530988439515,
            3538743929058160676089941510944446471328206128181089191698294681395283350634,
            2237323887625829376688499391724463079800440218706938890348123328923812339540,
            1130243682937917620268960140299047146267651359700302322475928409943780708841,
            968824490565703233624917328080014063543033369775191861705550634803488842237,
            2743147817315990265910292270103689492773580890248797577167173808684942134618,
            3307231726141690678435107384634183759474746138470279093900943135752201122343,
            3246639577066292945155847586969681707925711450662148133676908987881053587389,
            1976540520851311785177237983151920146849268320997464068882835193888897434677,
            1478230809993789541851508266116878391566461798022496893302139807357612185778,
            2538580790102586056951007071153803308585550117516549050917890210213482453596,
            681694098543859688979851728866180786864803715174946424092272604171005341649,
            195509928307268477453448376910729959903374121249553994920292473604367885558,
            752251690398830480661919812146339549507934203404766535095326405864961821086,
            3601189844361896426093010378258379876630876950968374235062911968198250116723,
            3219855881302516032040688075349197791649613046841442341089106845938459662655,
            2457663863926258618254558098989697635241904056398302960446859000007379541938,
            3394828220800766976232898928139909077948969211348446967578632179634589092175,
            2314792589881435173027280671636923588016928894886373465528594347937312456291,
            446968282587854820129703045800054325447165835250047366001807089539571936662,
            1636023701246705037290051059860817901507889613902473935131498368546106618341,
            1320537659183647086105449736350515510491488630070161944519415006412201638119,
            1882992557344655897045951439107111102390113069972829783751641741633099381950,
            1226453080695503424910762434245739328700619351630763086102816343096765569266,
            78860202055988636582805402732021190839338773724933504544661123448261633376256,
            99952646476384034188963444990416773575134266832695992717979041530790222495744,
            84231937717901355098931567281508252191282863280466560419031001951258856652800,
            72812969004107050579943382908045439422513282621923642179475448771676408381440,
            18088080609777658713274328145815745293380597090861629095997539928680096071680,
            9961937583606369899904528919683433453808689042810720749599753591335107428352,
            86380268311127091158987960472974151209902696784574945409126899879071509905408,
            92941711466163485405360371463102689815915180270866032756874927577475420520448,
            39192157247355207307318220341210651289220981650645622137439991735151256141824,
            35770118751754406562570137339888109795184345622459281599852220029249586724864,
            35514689348630054142395812471951375716013132047557303838592237314286483931136,
            7454241264910516681134676123498496241128105946227756868718278101941375467520,
            38217317978372371195770144252287606960143531991321261832824678155174943916032,
            100274428656655810740905473935548890914633004360326031806260148597996365283328,
            15781652542349469153531380557475262943601071344327967441964471344819328778240,
            102644281923360922664472068044115525546303366417893802814255790446796792135680,
            40921612758727626361306002318333523591955883534966101872270904480958248910848,
            25484108248705744318108968805077331938586197436035707096456456464365376241664,
            93865610521054945322126429854955026751998569772252170349515038995904169246720,
            57366584273179256242323470362550167321544640026860474983285570658985175941120,
            7142114685328665482802081273374931694015566396945987868572531441557993160704,
            96551190928808060683849188049505461939967955184315364701301035249806709096448,
            72324189652130058304426310112007801677966936764064660671584837874192501178368,
            2871148815556164713788607942272269170063697741911550007653158726435719872512,
            15062790078470220360984539771511423429149894328855264189421769052452357668864,
            38620877157280640811719287914941321491786586826705306694934446389651639894016,
            23952928014149989103326543104319310758827351927091435418437556422337403813888,
            112324617036812240532350842300366931153925083051828842185069410986225163042816,
            111230754803096775259869255558765241718673106836418174826048618741084926771200,
            42920606750918472418196577414699905764458469779715999775338274008854815571968,
            103280449840742729990242743237546232089909119772868286271808914826820770070528,
            115143554733226970053719079416163221528933956237667119318234335718639382036480,
            87886607883915195043214077748399863086347579217829584964439690274090619240448,
            33695689309274377061679097942618961856189207904775508684196088210240992968704,
            108410244722007701115700119989894825329250037597392417609583834112573793370112,
            91982463961207742796981920496673376135622754344685006952872651639951697379328,
            79268325532588315705231261407476413324385287623313341633976891694547705266176,
            48061873611420542327696921991206038240992360459780809383971292749328631726080,
            41897552333815358515591520950117183102796275601815483282023949067896099962880,
            61313307085533309478819061540498854441659706668437777639415199278941687775232,
            6777510059723959159848671874087548977352492383628229162455724019966055284736,
            38930256276607599203003487671190630469924287198160230702102585725923088138240,
            82081095972947147876763676187330057624620129514204315440179379309791246548992,
            29380854731051557766420886488665986204637740871139330788623567610367088525312,
            101647836786952167470313029952396476540077803377140819616803725462904716132352,
            102319352742023717217666558963159731431385423916688971545897139322414155431936,
            38503980727121951316109657919714065478503850846546114985034307836120930451456,
            102397437653855405119824875178295463708105902504200412524917911276849245192192,
            37510496688952043612617593796161033270744626727512259237742546620763026227200,
            77532859527752137847187109033414152138536401951793297979300225504394340204544,
            419381171841090917441425185867441351899473861068829162143271649446077661184,
            74333575848114801160186865657826896763980424276314051834294617467201047756800,
            80232049643800831879345570293923630363829221697990038725071820723048991948800,
            66597411237826545880786419036956359217466563555858725861725600067438426193920,
            3083025086375263920579144631043339181092041455663196532467807838908956278784,
            39128684165899870278671735856357873606761644949049527240843378816910020837376,
            57465505320909804390512698237741594625128483405537340182342349363224244125696,
            53540572646241805678043441055944002120227426492671089711492923171836620963840,
            55031845626120038487456394151869809265045838887981447679353602761567812714496,
            27759946670720079502066282922085793898164019616624067396909110420326204833792,
            8134287173109375638449532973874620066899064572677373676554707167755884298240,
            54409929576761152457231898819313820843165492443563340372742810865432346492928,
            90408436184233065495782831489359427803466151751485141281675206466427961737216,
            44135839854407639644109613370144047407727589730335494740697499339602079514624,
            46732878440199587406679379497132434709561256146639212862690682223369721479168,
            2707535326059890836963889121156373166791832699508982478856019785582437728256,
            87732260591621445693984099783570137818929185471946037909799997784819419316224,
            41726683210225196585825860895630850420152129822038608978181933447927769858048,
            88022951105571864721081880396095465180638620238010321915695072761085666787328,
            52180590367083577395850740201851862012457509819581214350136691938390532161536,
            3119751662953178398101184558332263911731094532897023291653318937977513050112,
            44501814924603268253016745572518390396177353780047412391341880331991896817664,
            86229240513967184192113894937007891301423802334409404319898425373604714643456,
            76392975520609226867704453547266624753421267166138897514074265112246241722368,
            27687263140065755361934939440890117062770198511452455339792500141278554488832,
            32900824021122361010465475602311544426892525583004765689287968704119600840704,
            113435352035301012036848376374196304837532374591079498020904304321655681843200,
            101278420183884383495165434842254393973269893643708829829909481729922709848064
        ]
    }

    public fun get_fri_queue_2(): vector<u256> {
        vector[
            8654,
            2226079386214278420906153503340923489526347366548276438723928551992982171948,
            2375136420783750489738929182065504335814224067183861948971564101403346500150,
            8864,
            1923149621016132790394575711631312993006706015416814945231394181938094463632,
            2627454844437363116827067456316954382581502224402037760828138156698495111789,
            8872,
            767574570518613834983533127200219454401562743194306943958373011601583952170,
            2442116719202745222317050365334421108534089441074570261096236561234135436071,
            8960,
            762383334152182893193335263726878399519311612359503047635132496747223741506,
            2481192966350484284781444286452713873306899553191885257778978001244301921332,
            8962,
            2405261806251725311426231814688740955890501951757896913682362542374629850708,
            1141176329281216991781143479671276472994379600262502016245711296542246436304,
            9219,
            3038390542940552793411876443207024175895153170254419672188333805469306539131,
            2062760550031380183909143446084780248931376704985002047397605892339921584165,
            9582,
            294396362018553964139426357003714418359546866173962731970629885263811653145,
            2899499583545178436094809269712372304569463354395376710816693221599893802344,
            10484,
            2931450473205302777092283559532321299159077945420576677059064860820387532914,
            3366481896698015449131051632011887423328937088850337029112238311692665428694,
            11800,
            1133060430192224432349600287414081596346022262312642227575757988117225091083,
            3076416491598535669020108541451298082586988215331874867805586518314666308550,
            13343,
            2002710608025950652062572127119155198661599968212352229052036842071332305528,
            2410316126026384842946346537466941236142683163073530113095117903903621238674,
            15010,
            313517508408661277172714980685686291952302470486383201224928850425639426269,
            511592720295445574202769613327480357557510365119464611980506986273700541739,
            15254,
            1068580032210969310820441971568870567141187468788959862509293365315801440493,
            485902614905052400872806737597683652478874344960466214287204218509615193446,
            15573,
            1962308160764865595466980106400078730898556734987881690710010303168846566254,
            1443019802061203168167750023229440256316286039877323609869365872877115275173,
            0
        ]
    }

    public fun get_evaluation_point_2(): u256 {
        917493136792288213169604550256575848298515592819701684495944720164282831845
    }

    public fun get_fri_step_size_2(): u256 {
        2
    }

    public fun get_expected_root_2(): u256 {
        5202765376918263502155242869247823481427229702139167258190584318600719368192
    }
    // 3

    public fun get_proof_3(): vector<u256> {
        vector[
            732760739612308100049906584047157783110714348888046202826270876912749598168,
            2338447598008876670954408114629385874830756656403809740235239540761808549504,
            638556572290486187753196286237442199190294557105040487593893779120969081488,
            1560022457373993664620468419788331868837658596964560113957949278339961003479,
            488775989980186780338997630358691189773662780715959734843914642824287457150,
            2226574320078370713032093352652975126739611360964678968588807817522329842825,
            2306852593192277452696224567240502847832055179648525083552593101645241869971,
            3472179235766154838434579711205657159041991595865937080682399597754573232441,
            1078811873943764892026059989281359364229959265376607547640844546763733642580,
            2321547384977231267188281809340936263451819538224694499302431981292523952839,
            396506576250321341311648063955301005779204167693615039340334916880455957765,
            1968679894746215596443429273082638273230425887216288383216633131591329585111,
            3382230657072057965757469887230919947278019533975846497395189942665749793893,
            1372726906340320359754829656383702772889616887275002011690574747988728995550,
            150065324774634707579099029180307454370480205268689392952418091996225196906,
            3451415773821267557171776638841348908987774750256724545355898848297761714011,
            267493715973173520137729946743700873520151349798462045235219687248252717929,
            1350029781887954988918868638236712584840524948775591756228015179532925636209,
            2033959568180207193617265217126303751378049450303445937070151091346441983816,
            1759046280763564047482135773004252637790798834143069146917632628771131403888,
            832860108441282049273441613953043646439890145855897997074121361309246926108,
            3259061487805176187049200388349468399004395860492090070831623810058498880878,
            16045754007376442276411162383919808795781809959846918478916552560260947600,
            1919550401839599907213679961682240847323459033745128193518592511113373324711,
            344865302256255248290841155532676934758027902395073058929647380768343504456,
            1308813998568520478930508065159910277780673763321704825002221420562259146235,
            2637186192668429942905471141369815921708017028565565133033422677087183559146,
            901600540878637026265055640570027526935243769732114998898326672838432891138,
            180533624594242831517051553101312105783756133334435279789608587085352741205,
            1130124878889067962321316838319936072823603507795524179607806893327490202989,
            227775348505773234034870440594247730467578420661903277029863181902068052530,
            3258500569336696664293407175339158594662942265854978861477768001827957808537,
            1016175779329597067412139761120729306653279008166815524377884258471290387629,
            1672373475343457863474524195289625613193817137321634988969329982055492605881,
            784396279877789239626135564210194383657057511207828232848610618012009464894,
            2318204926736945130167472261621413091796612381112572912286347717645630696535,
            977562448427365711715708718123914784609792131703648629091881075738335239607,
            249113228450294526795544620887194515544064477514412499360054426425258838563,
            3408749293742637593905960949969969659542745209625238676320687278856648035669,
            2275383394714085644159569493909698620020788897726292060869643123848320032040,
            1410015480582166465653302427109016412489280288873218999042793937181920367159,
            893033741806628679651763142664970048243838845151361667768906506099875966973,
            3385150968012464794816192940673314535346902404249108018529099192781100148745,
            3078865843213230602540993466675248506455008928402530662009658643709402245032,
            2201348662179545169134389468444779773286239865205167102728358911713365092270,
            249154481998266292241682790014576345745966483615649632886375425717747720128,
            1166993418982130549812525063517673144407844553939359706794801639976651182017,
            2883227819624228151460580420683677916547276517414533744759606658090231351298,
            3440001993271458528817826783707763532641976780610963062414820706525500691140,
            2636783663312794536593386201765274285682554263289950872276146085258638105447,
            2182093569018220342508762184701792118794567874411565930443394123456788727081,
            2960030828398354867640668653708779714225291533581639001846880096592979935473,
            2421263317144373664512537164275790715693590494234228177529752160786785885523,
            1423437469147696526047456924361914663354630737042167642760615032462333208925,
            258500037246654331886083846164080832282491358291349007339529803383698647779,
            1390250760701923057645441280460576600508264987349848974642264794686547805924,
            1133345576039136117336381536567387552825895459972482981799367699327931261669,
            2277410994385721107546856070952836809538552659559870367814304812158930610038,
            1060806370357613580307854981257787102967814801511121015599577288051388006830,
            2152697447236218565223797830941477339296844030779705088388614659428547289619,
            1296308185668586327126942576294973464592835893173555381549815233827821674122,
            2414361325547869316551563296637692672188553624183296592991726703734491614940,
            2476328822436766450159451345607799492762927136891545932609674334001122733615,
            1985598347737655921604560397846127353854517502114499142903903976320263440407,
            169835116457147402951142552629357406178039830308352943607711798794596555174,
            134561089816456934655780106542018741435698016410947688581485306786085881953,
            1203597762336374060202354349555698492997041604611097740518257265298145224069,
            3272940371973108962582782466811896182238976124429953703088649042425447566956,
            3545970982844847052643288226158340897568489162123073787678983387916653880780,
            1411639025185188744025698943433223440944727246755781436553999362281206822052,
            3204970823995748722565777136172563653929906606186141290963696057498962846469,
            1537920829295295799307255765718251979863865838310301406520158686798139305080,
            730720183998877596624788949943566686225088171654665915766322726264422767888,
            2598193165152133261698386383178852182755923361168144092349431003738590465975,
            9225870062283163643868761848836766945060247833351789216705866227624676438,
            2221214166452930869125775852872969760068612402503120325359312598340174255747,
            2971843402961368954590318983636866259554823784827412945892358440235470879653,
            1069086653667961785472672804603128442075547658908073030278661741718927267714,
            1867320977583477782337041705327996428568434075622690033106591457633416397723,
            3019224654013907397560903150070715123692969133763466549777583614967133981428,
            234547459265058059688187102543620462055036578784712714284314184847230539008,
            1052382013055978253478444205878791945360774497203916540207343990638479964007,
            2471452992961794771995558620386560106991680527035808285373369900208303317609,
            3044237569942223895835185054557367797354096935812930636079761900666066650915,
            2836554476964769863826293055000365537428309988223526229898978561539374931641,
            3245426627299617332166962151565041129734243347562338196140421602368411547713,
            2753878971938587878914908258732044778500405546787961710461021412789140572814,
            2300564061219776034007147984951197516612837858783742913729042739978888031037,
            169898012579507026449553934826352411905502755087500699476876223884490714019,
            2585445679329966610281585019317421821949531182167568964790352910424601788342,
            3314159857314988202500778688080708095074777598221474935898605552093829847864,
            76890601900160654391173487575924289054531270273482748498955661008085446557696,
            28951825798470463656369354931594974190285670571006168129961372439822544666624,
            93145385271435086251900341043870384042517493612831787708862239166905825886208,
            66923118917532383037660905289029915671010060788500092279817968773240660688896,
            5601094558871393084086079467005979760322703565816886774229669677245929619456,
            37994026881238091749584100113688151178427612059922769221572142962916456398848,
            62909192895601672020618314199482287758204345549762726029122523468902965444608,
            54643179649329660002824928941090254407873613659310396757669989821107312525312,
            40894983951613460764524216013972871623091167160791935313899661147302994640896,
            63300720062659416315034813687034907221501490313541081633579374390471519371264,
            79915481014682984344027423521317861693682967099698299861958165252326253658112,
            103700380785899053032231429209566089223467430199922401417401348046139405893632,
            28859861259175879471828113494011961416649423253652296722050682727877476089856,
            60529428021482789183736537771593621955340954298377799420995209836354598862848,
            111010085245744977141061156957134477393165735160472159095078544980654805745664,
            24172676853046036836329983701189738573423357745841104036021198403824447913984,
            63401492333866799468976786047668330247365085275292703152968718184401118167040,
            100515595210560856476979746904673781569218446145158102628315492814354319933440,
            22723671336562612944086893304714812591123017843344654249464448934751980486656,
            108550097292081696153359139130692540256021540875455684127124935516815112536064,
            4357844704525617802732011033826408159229758440882064041139377120917233598464,
            115317825720353045292190328112615858108465093126915797493968526651932262006784,
            17177635450669318330966367852162198846462181076275519748195337029267971112960,
            14300615902126688278160861846695061226488272360317538535029993354639766978560,
            68210246324623309451647770972842689575089608892511994973926378389041745756160,
            98006232981289090302941952807095795116342422415893199891453556586683524186112,
            35505728897003609232602689599448188701697431110221509847618095129777982668800,
            99247719312493621191216237138715418326047182359114924954277240968831249154048,
            94773302829938184098267674046972282351717911251742906141277819560064299565056,
            11533535448849096551073919565303581739172901376199071386901284060590791196672,
            72013470930071927689571417020584630954726606435014736219667691535686973784064,
            81366984756620487242087727521570511372019046122567093553809796062903808294912,
            31553690834848665785135364493180715629840897940645096016867057446683412529152,
            33029591538002884406278456134268892007453664436380138850783547830911214026752,
            23007612059980365748768644097143500608953148767878486604441136995276056166400,
            27403190147157982139224748190408928796603433306013731441174832686315109089280,
            73353988529160710413867864854303840515375332474148459341482685918530706079744,
            8863133246912073919725729664844694757854869325273629849180981472946018058240,
            106731546803291876004613481679366856178792288548104701236748261954284035244032,
            90669340528385738153876711353407966053393833362943740789059938184310158262272,
            94351959191024090532276840756405772278913618861656425746351774461298923798528,
            13002368248557070093345975526193129152931693756507030378972261307968007438336,
            73885102379370265882899501399139246387277325098860691414646190417229574569984,
            24542800480304932028352158726021429199102088647155207796387385543530339368960,
            35098348268927815882498810148773628339334002779352017488506186195608281284608,
            105072401490029779668187748513559826553379525545751518984629772290513663164416,
            102094388824294191351768748288791002607796382828294579347228684485096468643840,
            22575073094160474128193761665775313518628617296966234964982505448265440296960,
            54719678532908290406650199610833569087816119239684696396527856829022001430528,
            82466741908136861632941961671838635168054285094684843481316260699376122331136,
            15189527755055422383089451286540096443718575499544038891427539161496699273216,
            10387969987781677490783214504823745473919162969162462445081752738718942232576,
            75537072253761496646449566421689875867780031961228128188038249087926647390208,
            41967463686585267874106621335234319048417631600921488220321739121240771133440,
            11184884091912422143201333657384466339594093696771513297082178017696059228160,
            1537759790339621306152862554670867450932886007341365250781192886756157947904,
            46886339846340228004196120033506833537209493176283232662896464535949246726144,
            52784624446692279950991982544156628784451417326487557617816734869354186801152,
            38938022765412481306463395288423517672206661291924127542791101233441974255616,
            77254501810828225518401933038541147530713654226348510966795100365991899561984,
            5728309279570382091489129544846569442147476270092894670667888629124815650816,
            42149101614411967109478394890585953081200836286153048717816467177927560134656,
            48004147803371363381802363945970192358899509295460035660422447377848725405696,
            96218705869522881613213016116275846030524400877096346564799635432483946758144,
            84192715110664973316759820087924669450057425548357705819724243181119003951104,
            38873906982163031960302224903303189145095953782162107739281339354939545092096,
            69111307204538712231544308338387878329704112116296470605062925630630558433280,
            54682510791781575482551417219351666278017040855716314467949639185980521971712,
            114574442615783184300274072706242909487906380319472029892314306483489964294144,
            114813048609331945143458625588376082591249811541207100336937895888544226869248,
            47912160173146632519631275169088263793009691898871686064432327840955128348672,
            6639056206167440201329187999255794588153887003571015212713721618327985455104,
            26457118856390199106825382332801919586112139693201858897098624446857914351616,
            66293407024099532386841133844282440900015707770593823350087359131572781449216,
            56719656442774069529025169110686198056364581621226905312116463543032439898112,
            58501032360052653085393975510933585065061940325117103759602397376714729586688,
            112539957873022536750283707432633705296690845086265129134144985044502425108480,
            69113254518834274536103261051596567421852765442803906806584364413420329500672,
            101482138972401600788429219669766998179346069770849922795153404369508100997120,
            35522271978317548065624161127503886579075336515170475684298053146293733163008,
            14922327040860854633826098379424667287340527635987743791090219499426609627136,
            97280385865253185245724740263198329206320603092247005005822401127277393870848,
            14018116634043680998372686155590241472400429819508644686840444939877404901376,
            99493025085141591031945331063157622467245330248327409119010298061025473200128,
            59341618779705626448420190480279489363574589824825021978526030742120503967744,
            69618473214628358097999855414985888418313055814079116581341497239400760737792,
            29142762731837157475933931618855917341009778385349511580817846669306100711424,
            98155492537457150118311847841645382016565681283298135401014283578507423383552,
            12561824058702667249435617416993540091039187306700952857794268373114385596416,
            51565135592278722351325934697075386848462051869780198159629752931586003697664,
            69979676134069579218571058930276270862701936934223935370733412043783516717056,
            108657328282277802354558025463339819424363091560174656893534855832410536280064,
            66438204530674395962054503288603050425741700842441066854881171963458011267072,
            64131362067177888437207812098106844179865280529305744301973264821547956174848,
            46577914729266175406677411468375276090071868737620475012100798923180397821952,
            23405217046433683422781253701987444979054411621263686439347339887254851026944,
            64544468677253839786675775411039371097795217101958754267139471054074185515008,
            113931171266937219620609785879270964604992456272345120306688393130923274534912,
            111143557704057102191391414138246547725307706309972543569380721168830934548480,
            110860655711444349854461643816225722843923446948770261067257023595879164018688,
            46840717312198268492084117480132321914024177609728532251645337403454142808064,
            68440390247805339410175106749096156575753570593239158880662732987535384903680,
            66501134395927002834264032907260669568642171172362409493089229481845494644736,
            78610869832528399727189072777630654688557907079722577505880569386728526184448,
            114850986350390194987512784706435271781065479323470753998205274719731086000128,
            52632754682768734903846740408724542847820505663926526929525610273823329878016,
            24363610071119668937916408936011333833177826593172464535404137128778010722304,
            68209196664397503312193573711246814134746843615088486481905808012132147527680,
            99914800062639277712631289053936604978404341905810277090752383926578997886976,
            15454604719652172672855510878030281439712630441624602285040387558326658924544,
            81883511606353927931629085486578520968731663621562623521105390579287454646272
        ]
    }

    public fun get_fri_queue_3(): vector<u256> {
        vector[
            68842,
            2964178946110064358991726962687892125811805618747981051340918888528792149605,
            2179683427920472696291350577048132027566530074554770687235446808381170104740,
            75704,
            2103094102915868483382485829173571396270087725632841249210530049472424431841,
            2479596287378622959513567150060924229204175125306857273715736723758389236318,
            80587,
            1798636197358091986020677304753686596407232309857363392050569119004515665288,
            1276280021350835536877635448007346376375629566169883884721703797525132952779,
            86673,
            1223919860614697179665648943701441038121903949120965235434568549706881265714,
            315285769684436180317884585551657710036431429370134602541400631969325311314,
            98467,
            1498837460801827753244815055028767727101955870935055090297998458035615512878,
            886174992991936454854555347243570745158880282692944820968869513404805391082,
            101247,
            401382385200356601733921431908710955160228380430776219606687202903303544395,
            679814886334400165039259936221294035995228207839446638120957569565762850347,
            102074,
            107169631283831902545404617598779270567619544128856151074130368670375305073,
            1658489653615862222132196732940191116616212573463363599252528863907631515768,
            112906,
            524467796028629916135088306351772443014515171851601370770980672297816004568,
            3054550940202130034617898482251712777924047495173323457299213297263826350828,
            113760,
            3376618749243009688521553232710707914835694730136690370108761279729079575438,
            1058561548859322008983466353839301649035915957137925653166306645978868347203,
            114976,
            1227923646611606553177690648991829647219422103852733855662008292391993749234,
            1899443339253771681117963117804100042655863677622846446674184778656382944186,
            115525,
            235160462280836882059278614936884803584031242303237407732165794589913142069,
            2309872502305684530821077676648359152149200585228250214134985515759438262321,
            119020,
            573842828530156600986657311356120176821431616140699737178615667697957614495,
            743000622407137865621501727376975648288989174439365349123213734935762649486,
            124339,
            1546530425735562875072380887378689929310882182235024380357204143554321321082,
            2752221987707151453287287390473883776897193346908145369312214213686196014690,
            0
        ]
    }

    public fun get_evaluation_point_3(): u256 {
        1127319757609087129328200675198280716580310204088624481346247862057464086751
    }

    public fun get_fri_step_size_3(): u256 {
        3
    }

    public fun get_expected_root_3(): u256 {
        9390404794146759926609078012164974184924937654759657766410025620812402262016
    }
}
